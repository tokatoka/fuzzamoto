use crate::{
    connections::{Connection, ConnectionType, RecordingTransport},
    targets::Target,
};

use std::cell::RefCell;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net;
use std::rc::Rc;

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
    pub fn new(_exe_path: &str) -> Result<Self, String> {
        Ok(Self {
            actions: Vec::new(),
            sent_messages: HashMap::new(),
            snapshot_instant: None,
            transport_port: 1337,
            _phantom: std::marker::PhantomData,
        })
    }

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
        let actions = self.get_actions();

        // Create a more readable representation of the actions
        let formatted_actions: Vec<_> = actions
            .into_iter()
            .map(|action| match action {
                RecordedAction::TakeSnapshot => "TakeSnapshot".to_string(),
                RecordedAction::Connect(conn_type, port) => {
                    format!("Connect({:?}, {})", conn_type, port)
                }
                RecordedAction::SetMocktime(time) => format!("SetMocktime({})", time),
                RecordedAction::SendMessage(port, command, data) => {
                    format!("SendMessage({}, {}, {} bytes)", port, command, data.len())
                }
            })
            .collect();

        println!("Recorded actions:");
        for (i, action) in formatted_actions.iter().enumerate() {
            println!("  {}: {}", i, action);
        }
    }
}
