use bitcoin::consensus::encode::{self, Decodable, Encodable, VarInt};
use fuzzamoto::{
    connections::{V1Transport, RecordingTransport},
    fuzzamoto_main,
    runners::Runner,
    scenarios::{IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, RecorderTarget, Target},
};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;

enum Action {
    Connect,
    SendMessage {
        connection_id: u64,
        message: Vec<u8>,
    },
    Disconnect {
        connection_id: u64,
    },
}

struct TestCase {
    actions: Vec<Action>,
}

impl ScenarioInput for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = std::io::Cursor::new(bytes);
        TestCase::consensus_decode(&mut cursor).map_err(|e| e.to_string())
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
    _phantom: std::marker::PhantomData<(TX, T)>,
}

impl Scenario<TestCase, IgnoredCharacterization, V1Transport, BitcoinCoreTarget>
    for HttpServerScenario<V1Transport, BitcoinCoreTarget>
{
    fn new(_target: &mut BitcoinCoreTarget) -> Result<Self, String> {
        Ok(Self {
            _phantom: std::marker::PhantomData,
        })
    }

    fn run(&mut self, target: &mut BitcoinCoreTarget, input: TestCase) -> ScenarioResult<IgnoredCharacterization> {
        let mut connections = HashMap::new();
        let mut next_connection_id = 1u64;

        for action in input.actions {
            match action {
                Action::Connect => {
                    let Ok(stream) = TcpStream::connect(target.node.params.rpc_socket) else {
                        return ScenarioResult::Fail(format!("Failed to connect to the target"));
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
                        let _ = connection.write_all(&message);
                    };
                }
                Action::Disconnect { connection_id } => {
                    let _ = connections.remove(&connection_id);
                }
            }
        }

        if let Err(e) = target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {}", e));
        }

        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

// `HttpServerScenario` is specific to the `BitcoinCoreTarget` and does not allow for recording.
// This specialisation is a nop scenario for recording.
impl Scenario<TestCase, IgnoredCharacterization, RecordingTransport, RecorderTarget<BitcoinCoreTarget>>
    for HttpServerScenario<RecordingTransport, RecorderTarget<BitcoinCoreTarget>>
{
    fn new(_target: &mut RecorderTarget<BitcoinCoreTarget>) -> Result<Self, String> {
        Ok(Self {
            _phantom: std::marker::PhantomData,
        })
    }

    fn run(&mut self, _target: &mut RecorderTarget<BitcoinCoreTarget>, _input: TestCase) -> ScenarioResult<IgnoredCharacterization> {
        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

impl Encodable for Action {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        match self {
            Action::Connect => {
                len += 0u8.consensus_encode(s)?;
                Ok(len)
            }
            Action::SendMessage {
                connection_id,
                message,
            } => {
                len += 1u8.consensus_encode(s)?;
                len += connection_id.consensus_encode(s)?;
                len += message.consensus_encode(s)?;
                Ok(len)
            }
            Action::Disconnect { connection_id } => {
                len += 2u8.consensus_encode(s)?;
                len += connection_id.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for Action {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let tag = u8::consensus_decode(d)? % 3;
        match tag {
            0 => Ok(Action::Connect),
            1 => Ok(Action::SendMessage {
                connection_id: u64::consensus_decode(d)?,
                message: Vec::<u8>::consensus_decode(d)?,
            }),
            2 => Ok(Action::Disconnect {
                connection_id: u64::consensus_decode(d)?,
            }),
            _ => Err(encode::Error::ParseFailed("invalid action")),
        }
    }
}

impl Decodable for TestCase {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        if len > 10000 {
            return Err(encode::Error::ParseFailed("too many actions"));
        }
        let mut actions = Vec::with_capacity(len as usize);
        for _ in 0..len {
            actions.push(Action::consensus_decode(d)?);
        }
        Ok(TestCase { actions })
    }
}

fuzzamoto_main!(HttpServerScenario, BitcoinCoreTarget, TestCase);
