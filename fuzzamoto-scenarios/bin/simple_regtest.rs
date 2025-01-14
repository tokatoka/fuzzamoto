use fuzzamoto::{
    connections::{Connection, ConnectionType, TcpConnection},
    dictionaries::{Dictionary, FileDictionary},
    fuzzamoto_main,
    runners::Runner,
    scenarios::{IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, Target},
    test_utils,
};

use bitcoin::{
    consensus::encode::{self, Decodable, Encodable, VarInt},
    hashes::Hash,
    p2p::message::CommandString,
};

use std::io::{self, Read, Write};

struct SendMessageAction {
    /// The ID of the peer to send the message from.
    peer_id: u8,
    /// Whether to force a ping/pong roundtrip after sending the message.
    force_ping: bool,
    /// Message as (command, payload) tuple
    message: (CommandString, Vec<u8>),
}

enum Action {
    /// Send a message to the target node through one of the existing connections
    SendMessage(SendMessageAction),
    /// Advance the mocktime of the target node
    AdvanceTime(u64),
}

/// `TestCase` is a sequence of actions to be performed on the target node
pub struct TestCase {
    actions: Vec<Action>,
}

impl ScenarioInput for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        TestCase::consensus_decode(&mut &bytes[..]).map_err(|e| e.to_string())
    }
}

/// `SimpleRegtestScenario` is an implementation agnostic scenario testing the p2p interface of a
/// target node.
///
/// The scenario setup creates a couple of connections to the target node and mines a chain of 200
/// blocks. Testcases simulate the processing of a series of messages by the target node, i.e. each
/// testcase represents a series of two types of actions:
///
/// 1. Send a message to the target node through one of the existing connections
/// 2. Advance the mocktime of the target node
///
/// This is essentially the equivalent of the `process_messages` harness in the Bitcoin Core:
/// https://github.com/bitcoin/bitcoin/blob/3c1f72a36700271c7c1293383549c3be29f28edb/src/test/fuzz/process_messages.cpp
///
/// Using btcser's custom mutator is not required but recommended to fuzz this scenario (see
/// `grammars/simple_regtest.btcser`), as testcases are encoded using Bitcoin's serialization
/// format (`bitcoin::consensus::encode`).
pub struct SimpleRegtestScenario<C: Connection, T: Target<C>> {
    target: T,
    time: u64,
    connections: Vec<C>,
}

impl<C: Connection, T: Target<C>> Scenario<TestCase, IgnoredCharacterization, C, T>
    for SimpleRegtestScenario<C, T>
{
    fn new(mut target: T) -> Result<Self, String> {
        let genesis_block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        let time = genesis_block.header.time;
        target.set_mocktime(time as u64)?;

        // (connection, do_handshake)
        let mut connections = vec![
            (target.connect(ConnectionType::Inbound)?, true),
            (target.connect(ConnectionType::Outbound)?, true),
            (target.connect(ConnectionType::Inbound)?, false),
            (target.connect(ConnectionType::Outbound)?, false),
        ];

        // Handshake and ping with the target node
        for (connection, handshake) in connections.iter_mut() {
            if *handshake {
                connection.version_handshake(time as i64, true, 0)?;
            }
        }

        // Mine a chain of 200 blocks
        let mut prev_hash = genesis_block.block_hash();
        const INTERVAL: u64 = 1;
        let mut current_time = time as u64 + INTERVAL;

        let mut dictionary = FileDictionary::new();

        for height in 1..=200 {
            let block =
                test_utils::mining::mine_block(prev_hash, height as u32, current_time as u32)?;

            // Send block to the first connection
            connections[0]
                .0
                .send(&("block".to_string(), encode::serialize(&block)))?;

            target.set_mocktime(current_time as u64)?;

            // Update for next iteration
            prev_hash = block.block_hash();
            if height > 190 {
                dictionary.add(block.block_hash().as_raw_hash().as_byte_array().as_slice());
                // Add coinbase txid
                dictionary.add(
                    block.txdata[0]
                        .txid()
                        .as_raw_hash()
                        .as_byte_array()
                        .as_slice(),
                );
            }
            current_time += INTERVAL;
        }

        let mut output = std::io::Cursor::new(Vec::new());
        dictionary.write(&mut output);

        let result = String::from_utf8(output.into_inner()).unwrap();
        println!("{}", result);

        for (connection, handshake) in connections.iter_mut() {
            if *handshake {
                connection.ping()?;
            }
        }

        Ok(SimpleRegtestScenario {
            target,
            time: current_time as u64,
            connections: connections.into_iter().map(|(c, _)| c).collect(),
        })
    }

    fn run(&mut self, testcase: TestCase) -> ScenarioResult<IgnoredCharacterization> {
        for action in testcase.actions {
            match action {
                Action::SendMessage(SendMessageAction {
                    peer_id,
                    force_ping,
                    message: (command, payload),
                }) => {
                    let connection_index = peer_id as usize % self.connections.len();
                    let connection = self.connections.get_mut(connection_index).unwrap();

                    if force_ping {
                        let _ = connection.send_and_ping(&(command.to_string(), payload));
                    } else {
                        let _ = connection.send(&(command.to_string(), payload));
                    }
                }
                Action::AdvanceTime(advancement) => {
                    self.time += advancement;
                    let _ = self.target.set_mocktime(self.time);
                }
            }
        }

        // Make sure all messages are processed (this assumes Bitcoin Core's single threaded
        // messages processing logic) with a pong/pong round-trip.
        for connection in self.connections.iter_mut() {
            let _ = connection.ping();
        }

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target node appears to have crashed: {}\n", e));
        }

        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

impl Encodable for SendMessageAction {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.peer_id.consensus_encode(s)?;
        len += self.force_ping.consensus_encode(s)?;
        len += self.message.0.consensus_encode(s)?;
        len += self.message.1.consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for SendMessageAction {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let peer_id = u8::consensus_decode(d)?;
        let force_ping = bool::consensus_decode(d)?;
        let command = CommandString::consensus_decode(d)?;
        let payload = Vec::<u8>::consensus_decode(d)?;
        Ok(SendMessageAction {
            peer_id,
            force_ping,
            message: (command, payload),
        })
    }
}

impl Encodable for Action {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        match self {
            Action::SendMessage(action) => {
                let mut len = 0;
                len += 0u8.consensus_encode(s)?; // Tag for SendMessage
                len += action.consensus_encode(s)?;
                Ok(len)
            }
            Action::AdvanceTime(time) => {
                let mut len = 0;
                len += 1u8.consensus_encode(s)?; // Tag for AdvanceTime
                len += time.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for Action {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let tag = u8::consensus_decode(d)?;
        match tag {
            0 => {
                let action = SendMessageAction::consensus_decode(d)?;
                Ok(Action::SendMessage(action))
            }
            1 => {
                let time = u64::consensus_decode(d)?;
                Ok(Action::AdvanceTime(time))
            }
            _ => Err(encode::Error::ParseFailed("Invalid Action tag")),
        }
    }
}

impl Encodable for TestCase {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.actions.len() as u64).consensus_encode(s)?;
        for action in &self.actions {
            len += action.consensus_encode(s)?;
        }
        Ok(len)
    }
}

impl Decodable for TestCase {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        if len > 100 {
            return Err(encode::Error::ParseFailed("too many actions"));
        }
        let mut actions = Vec::with_capacity(len as usize);
        for _ in 0..len {
            actions.push(Action::consensus_decode(d)?);
        }
        Ok(TestCase { actions })
    }
}

fuzzamoto_main!(
    SimpleRegtestScenario<TcpConnection, BitcoinCoreTarget>,
    BitcoinCoreTarget,
    TestCase
);
