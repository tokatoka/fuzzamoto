use fuzzamoto::{
    connections::V1Transport,
    fuzzamoto_main,
    scenarios::{Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, Target},
};

use arbitrary::{Arbitrary, Unstructured};
use std::io::Write;

use std::collections::HashMap;
use std::net::TcpStream;

#[derive(Arbitrary)]
enum Action<'a> {
    Connect,
    SendMessage {
        connection_id: u64,
        message: &'a [u8],
    },
    Disconnect {
        connection_id: u64,
    },
}

#[derive(Arbitrary)]
struct TestCase<'a> {
    actions: Vec<Action<'a>>,
}

impl<'a> ScenarioInput<'a> for TestCase<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let mut unstructured = Unstructured::new(bytes);
        let actions = Vec::arbitrary(&mut unstructured).map_err(|e| e.to_string())?;
        Ok(Self { actions })
    }
}

/// `HttpServerScenario` is a scenario that tests the HTTP server of Bitcoin Core.
///
/// Testcases simulate the processing of a series of actions by the HTTP server of Bitcoin Core.
/// Each testcase represents a series of three types of actions:
///
/// 1. Connect to the HTTP server
/// 2. Send a message to the HTTP server from a specific connection
/// 3. Disconnect one of the existing connections
struct HttpServerScenario<TX, T> {
    target: BitcoinCoreTarget,
    _phantom: std::marker::PhantomData<(TX, T)>,
}

impl<'a> Scenario<'a, TestCase<'a>> for HttpServerScenario<V1Transport, BitcoinCoreTarget> {
    fn new(args: &[String]) -> Result<Self, String> {
        Ok(Self {
            target: BitcoinCoreTarget::from_path(&args[1])?,
            _phantom: std::marker::PhantomData,
        })
    }

    fn run(&mut self, input: TestCase) -> ScenarioResult {
        let mut connections = HashMap::new();
        let mut next_connection_id = 1u64;

        for action in input.actions {
            match action {
                Action::Connect => {
                    if connections.len() > 128 {
                        // Avoid "too many open files"
                        continue;
                    }

                    let Ok(stream) = TcpStream::connect(self.target.node.params.rpc_socket) else {
                        return ScenarioResult::Fail("Failed to connect to the target".to_string());
                    };
                    let _ = stream.set_nodelay(true);
                    connections.insert(next_connection_id, stream);
                    next_connection_id += 1;
                }
                Action::SendMessage {
                    connection_id,
                    message,
                } => {
                    if let Some(connection) = connections.get_mut(&connection_id) {
                        let _ = connection.write_all(message);
                        let _ = connection.flush();
                    };
                }
                Action::Disconnect { connection_id } => {
                    let _ = connections.remove(&connection_id);
                }
            }
        }

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {}", e));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(HttpServerScenario<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>, TestCase);
