use crate::{
    connections::{Connection, ConnectionType, Transport},
    dictionaries::{Dictionary, FileDictionary},
    scenarios::{IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult},
    targets::Target,
    test_utils,
};

use bitcoin::{
    Block, BlockHash,
    consensus::encode::{self, Decodable, Encodable, VarInt},
    hashes::Hash,
    p2p::{
        message::{CommandString, NetworkMessage},
        message_blockdata::Inventory,
        message_compact_blocks::SendCmpct,
    },
};

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

pub enum Action {
    Connect {
        connection_type: ConnectionType,
    },
    Message {
        from: u16,
        command: CommandString,
        data: Vec<u8>,
    },
    SetMocktime {
        time: u64,
    },
    AdvanceTime {
        seconds: u16,
    },
}

pub struct TestCase {
    pub actions: Vec<Action>,
}

impl ScenarioInput for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        TestCase::consensus_decode(&mut &bytes[..]).map_err(|e| e.to_string())
    }
}

/// `GenericScenario` is an implementation agnostic scenario testing the p2p interface of a target
/// node.
///
/// The scenario setup creates a couple of connections to the target node and mines a chain of 200
/// blocks. Testcases simulate the processing of a series of messages by the target node, i.e. each
/// testcase represents a series of three types of actions:
///
/// 1. Send a message to the target node through one of the existing connections
/// 2. Open a new p2p connection
/// 3. Advance the mocktime of the target node
///
/// At the end of each test case execution the scenario ensures all sent messages are processed
/// through a ping/pong roundtrip and checks that the target remains alive with `Target::is_alive`.
///
/// Using btcser's custom mutator is not required but recommended to fuzz this scenario (see
/// `grammars/simple_regtest.btcser`), as testcases are encoded using Bitcoin's serialization
/// format (`bitcoin::consensus::encode`).
///
/// It is also recommended to seed this scenario with inputs recorded from the specialised
/// scenarios in `fuzzamoto-scenarios/`. Note: only inputs recorded from scenarios that share the
/// same test setup (i.e. `Scenario::new`) are useful as seeds.
pub struct GenericScenario<TX: Transport, T: Target<TX>> {
    pub connections: Vec<Connection<TX>>,
    pub time: u64,
    pub block_tree: BTreeMap<BlockHash, (Block, u32)>,

    _phantom: std::marker::PhantomData<(TX, T)>,
}

impl<TX: Transport, T: Target<TX>> Scenario<TestCase, IgnoredCharacterization, TX, T>
    for GenericScenario<TX, T>
{
    fn new(target: &mut T) -> Result<Self, String> {
        let genesis_block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        let mut time = genesis_block.header.time as u64;
        target.set_mocktime(time)?;

        let mut connections = vec![
            target.connect(ConnectionType::Outbound)?,
            target.connect(ConnectionType::Outbound)?,
            target.connect(ConnectionType::Outbound)?,
            target.connect(ConnectionType::Outbound)?,
            target.connect(ConnectionType::Inbound)?,
            target.connect(ConnectionType::Inbound)?,
            target.connect(ConnectionType::Inbound)?,
            target.connect(ConnectionType::Inbound)?,
        ];

        let mut send_compact = false;
        for connection in connections.iter_mut() {
            connection.version_handshake(time as i64, true, 0)?;
            let sendcmpct = NetworkMessage::SendCmpct(SendCmpct {
                version: 2,
                send_compact,
            });
            connection.send(&("sendcmpct".to_string(), encode::serialize(&sendcmpct)))?;
            send_compact = !send_compact;
        }

        let mut prev_hash = genesis_block.block_hash();
        const INTERVAL: u64 = 1;

        let mut dictionary = FileDictionary::new();

        let mut block_tree = BTreeMap::new();
        for height in 1..=200 {
            time += INTERVAL;

            let block = test_utils::mining::mine_block(prev_hash, height as u32, time as u32)?;

            // Send block to the first connection
            connections[0].send(&("block".to_string(), encode::serialize(&block)))?;

            target.set_mocktime(time as u64)?;

            // Update for next iteration
            prev_hash = block.block_hash();

            // Add block hash and coinbase txid to the dictionary
            dictionary.add(block.block_hash().as_raw_hash().as_byte_array().as_slice());
            dictionary.add(
                block.txdata[0]
                    .txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .as_slice(),
            );

            block_tree.insert(prev_hash, (block, height));
        }

        let mut output = std::io::Cursor::new(Vec::new());
        dictionary.write(&mut output);

        let result = String::from_utf8(output.into_inner()).unwrap();
        println!("{}", result);

        for connection in connections.iter_mut() {
            connection.ping()?;
        }

        // Announce the tip on all connections
        for connection in connections.iter_mut() {
            let inv = NetworkMessage::Inv(vec![Inventory::Block(prev_hash)]);
            connection.send_and_ping(&("inv".to_string(), encode::serialize(&inv)))?;
        }

        Ok(Self {
            time,
            connections,
            block_tree,
            _phantom: std::marker::PhantomData,
        })
    }

    fn run(
        &mut self,
        target: &mut T,
        testcase: TestCase,
    ) -> ScenarioResult<IgnoredCharacterization> {
        for action in testcase.actions {
            match action {
                Action::Connect { connection_type } => {
                    //if let Ok(connection) = target.connect(connection_type) {
                    //    self.connections.push(connection);
                    //}
                }
                Action::Message {
                    from,
                    command,
                    data,
                } => {
                    if self.connections.is_empty() {
                        continue;
                    }

                    let num_connections = self.connections.len();
                    if let Some(connection) =
                        self.connections.get_mut(from as usize % num_connections)
                    {
                        let _ = connection.send(&(command.to_string(), data));
                    }
                }
                Action::SetMocktime { time } => {
                    let _ = target.set_mocktime(time);
                }
                Action::AdvanceTime { seconds } => {
                    self.time += seconds as u64;
                    let _ = target.set_mocktime(self.time);
                }
            }
        }

        for connection in self.connections.iter_mut() {
            let _ = connection.ping();
        }

        if let Err(e) = target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {}", e));
        }

        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

impl Encodable for Action {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        match self {
            Action::Connect { connection_type } => {
                let mut len = 0;
                len += 0u8.consensus_encode(s)?; // Tag for Connect
                match connection_type {
                    ConnectionType::Inbound => {
                        false.consensus_encode(s)?;
                    }
                    ConnectionType::Outbound => {
                        true.consensus_encode(s)?;
                    }
                };
                len += 1;
                Ok(len)
            }
            Action::Message {
                from,
                command,
                data,
            } => {
                let mut len = 0;
                len += 1u8.consensus_encode(s)?; // Tag for Message
                len += from.consensus_encode(s)?;
                len += command.consensus_encode(s)?;
                len += data.consensus_encode(s)?;
                Ok(len)
            }
            Action::SetMocktime { time } => {
                let mut len = 0;
                len += 2u8.consensus_encode(s)?; // Tag for SetMocktime
                len += time.consensus_encode(s)?;
                Ok(len)
            }
            Action::AdvanceTime { seconds } => {
                let mut len = 0;
                len += 3u8.consensus_encode(s)?; // Tag for AdvanceTime
                len += seconds.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for Action {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let tag = u8::consensus_decode(d)? % 4;
        match tag {
            0 => {
                let connection_type_b = bool::consensus_decode(d)?;
                let connection_type = if connection_type_b {
                    ConnectionType::Outbound
                } else {
                    ConnectionType::Inbound
                };
                Ok(Action::Connect { connection_type })
            }
            1 => {
                let from = u16::consensus_decode(d)?;
                let command = CommandString::consensus_decode(d)?;
                let data = Vec::<u8>::consensus_decode(d)?;
                Ok(Action::Message {
                    from,
                    command,
                    data,
                })
            }
            2 => {
                let time = u64::consensus_decode(d)?;
                Ok(Action::SetMocktime { time })
            }
            3 => {
                let seconds = u16::consensus_decode(d)?;
                Ok(Action::AdvanceTime { seconds })
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
        if len > 1000 {
            return Err(encode::Error::ParseFailed("too many actions"));
        }
        let mut actions = Vec::with_capacity(len as usize);
        for _ in 0..len {
            actions.push(Action::consensus_decode(d)?);
        }
        Ok(TestCase { actions })
    }
}
