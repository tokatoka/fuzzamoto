use crate::{
    connections::{Connection, ConnectionType, RecordingTransport},
    scenarios::generic,
    targets::Target,
};

use bitcoin::{consensus::Encodable, p2p::message::CommandString};

use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net;
use std::rc::Rc;
use std::{cell::RefCell, str::FromStr};

const BASE_PORT: u16 = 1337;

#[derive(Clone, Debug)]
pub enum RecordedAction {
    TakeSnapshot,
    Connect(ConnectionType, u16),
    SetMocktime(u64),
    SendMessage(u16, String, Vec<u8>),
}

#[derive(Clone, Debug)]
struct SortableAction(std::time::Instant, RecordedAction);

impl PartialOrd for SortableAction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SortableAction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq for SortableAction {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SortableAction {}

pub struct RecorderTarget<T> {
    actions: Vec<SortableAction>,
    sent_messages: HashMap<u16, Rc<RefCell<Vec<(std::time::Instant, String, Vec<u8>)>>>>,
    snapshot_instant: Option<std::time::Instant>,
    transport_port: u16,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Target<RecordingTransport> for RecorderTarget<T> {
    fn from_path(_exe_path: &str) -> Result<Self, String> {
        Ok(Self {
            actions: Vec::new(),
            sent_messages: HashMap::new(),
            snapshot_instant: None,
            transport_port: BASE_PORT,
            _phantom: std::marker::PhantomData,
        })
    }

    fn connect(
        &mut self,
        connection_type: ConnectionType,
    ) -> Result<Connection<RecordingTransport>, String> {
        self.actions.push(SortableAction(
            std::time::Instant::now(),
            RecordedAction::Connect(connection_type.clone(), self.transport_port),
        ));

        let messages_rc = Rc::new(RefCell::new(Vec::new()));
        self.sent_messages
            .insert(self.transport_port, messages_rc.clone());

        let transport_addr = net::SocketAddr::new(
            net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)),
            self.transport_port,
        );
        let transport = RecordingTransport::new(transport_addr, messages_rc);
        self.transport_port += 1;

        Ok(Connection::new(connection_type, transport))
    }

    fn set_mocktime(&mut self, time: u64) -> Result<(), String> {
        self.actions.push(SortableAction(
            std::time::Instant::now(),
            RecordedAction::SetMocktime(time),
        ));
        Ok(())
    }

    fn is_alive(&self) -> Result<(), String> {
        Ok(())
    }
}

impl<T> RecorderTarget<T> {
    pub fn take_snapshot(&mut self) {
        self.snapshot_instant = Some(std::time::Instant::now());
    }

    pub fn get_actions(&mut self) -> Vec<RecordedAction> {
        let mut actions = BinaryHeap::new();

        if let Some(snapshot_instant) = self.snapshot_instant {
            actions.push(SortableAction(
                snapshot_instant,
                RecordedAction::TakeSnapshot,
            ));
        }

        for action in self.actions.iter() {
            actions.push(action.clone());
        }

        for (port, messages) in self.sent_messages.iter() {
            for message in messages.borrow().iter() {
                actions.push(SortableAction(
                    message.0,
                    RecordedAction::SendMessage(*port, message.1.clone(), message.2.clone()),
                ));
            }
        }

        actions
            .into_sorted_vec()
            .into_iter()
            .map(|action| action.1)
            .collect()
    }
}

impl<T> Drop for RecorderTarget<T> {
    fn drop(&mut self) {
        let Ok(file) = std::env::var("FUZZAMOTO_RECORD_FILE") else {
            return;
        };

        let mut recorded_actions = self.get_actions();

        // Remove all actions prior to the first TakeSnapshot action
        if let Some(snapshot_index) = recorded_actions
            .iter()
            .position(|action| matches!(action, RecordedAction::TakeSnapshot))
        {
            recorded_actions = recorded_actions.split_off(snapshot_index);
        }

        // Map the recorded actions to the generic actions
        let mut actions = Vec::new();
        for action in recorded_actions {
            match action {
                RecordedAction::TakeSnapshot => {}
                RecordedAction::Connect(connection_type, _) => {
                    actions.push(generic::Action::Connect { connection_type });
                }
                RecordedAction::SetMocktime(time) => {
                    actions.push(generic::Action::SetMocktime { time });
                }
                RecordedAction::SendMessage(port, command, data) => {
                    actions.push(generic::Action::Message {
                        from: port - BASE_PORT,
                        command: CommandString::from_str(&command[..command.len().min(12)])
                            .unwrap(),
                        data,
                    });
                }
            }
        }

        let testcase = generic::TestCase { actions };
        match std::fs::File::create(file) {
            Ok(mut file) => {
                if let Err(e) = testcase.consensus_encode(&mut file) {
                    log::error!("Failed to encode generic testcase: {}", e);
                }
            }
            Err(e) => log::error!("Failed to create generic testcase file: {}", e),
        }
    }
}
