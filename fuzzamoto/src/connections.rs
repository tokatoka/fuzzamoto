use bitcoin::consensus::encode::{Encodable, ReadExt};
use bitcoin::p2p::{address::Address, message_network::VersionMessage, ServiceFlags};
use std::io::{Read, Write};

use std::net;

#[derive(Debug, PartialEq)]
pub enum ConnectionType {
    Inbound,
    Outbound,
}

pub trait Connection {
    /// Send a message to the target node
    fn send(&mut self, message: &(String, Vec<u8>)) -> Result<(), String>;

    /// Receive a message from the target node
    fn receive(&mut self) -> Result<(String, Vec<u8>), String>;

    /// Send a ping message to the target node and wait for a pong response.
    fn ping(&mut self) -> Result<(), String>;

    /// Send a message to the target node and complete a ping/pong roundtrip afterwards.
    fn send_and_ping(&mut self, message: &(String, Vec<u8>)) -> Result<(), String>;

    // Perform the the version handshake with the target node
    fn version_handshake(
        &mut self,
        time: i64,
        relay: bool,
        starting_height: i32,
    ) -> Result<(), String>;
}

pub struct TcpConnection {
    connection_type: ConnectionType,
    socket: net::TcpStream,
}

impl TcpConnection {
    /// Create a new connection to the target node from a socket.
    ///
    /// # Arguments
    ///
    /// * `connection_type` - The type of connection to create (either inbound or outbound)
    /// * `socket` - The socket to use for the connection
    pub fn new(connection_type: ConnectionType, socket: net::TcpStream) -> Self {
        Self {
            connection_type,
            socket,
        }
    }
}

impl Connection for TcpConnection {
    fn send(&mut self, message: &(String, Vec<u8>)) -> Result<(), String> {
        log::debug!(
            "send {:?} message (len={} from={:?} conn={:?})",
            message.0,
            message.1.len(),
            self.socket.local_addr().unwrap(),
            self.connection_type,
        );

        let mut header = Vec::with_capacity(24);

        header.extend_from_slice(&bitcoin::network::Network::Regtest.magic().to_bytes());

        // Command (12 bytes, null-padded)
        let mut command_bytes = [0u8; 12];
        command_bytes[..message.0.len()].copy_from_slice(message.0.as_bytes());
        header.extend_from_slice(&command_bytes);

        let mut hasher = bitcoin_hashes::sha256d::HashEngine::default();
        hasher.write(&message.1).unwrap();
        let checksum = bitcoin_hashes::Sha256d::from_engine(hasher);

        header.extend_from_slice(&(message.1.len() as u32).to_le_bytes());
        header.extend_from_slice(&checksum.as_byte_array()[0..4]);

        self.socket
            .write_all(&header)
            .map_err(|e| format!("Failed to send message header: {}", e))?;
        self.socket
            .write_all(&message.1)
            .map_err(|e| format!("Failed to send message payload: {}", e))?;

        Ok(())
    }

    fn receive(&mut self) -> Result<(String, Vec<u8>), String> {
        // Read the message header (24 bytes)
        let mut header_bytes = [0u8; 24];
        self.socket
            .read_exact(&mut header_bytes)
            .map_err(|e| format!("Failed to read message header: {}", e))?;

        let mut cursor = std::io::Cursor::new(&header_bytes);

        // Parse magic bytes (skip validation for now)
        let _magic = cursor
            .read_u32()
            .map_err(|e| format!("Failed to read magic: {}", e))?;

        // Read command (12 bytes, null-padded)
        let mut command = [0u8; 12];
        cursor
            .read_exact(&mut command)
            .map_err(|e| format!("Failed to read command: {}", e))?;

        // Convert command to string, trimming null bytes
        let command = String::from_utf8_lossy(&command)
            .trim_matches(char::from(0))
            .to_string();

        // Read payload length
        let payload_len = cursor
            .read_u32()
            .map_err(|e| format!("Failed to read payload length: {}", e))?;

        // Skip checksum (we're not validating it)
        let _checksum = cursor
            .read_u32()
            .map_err(|e| format!("Failed to read checksum: {}", e))?;

        // Read the payload
        let mut payload = vec![0u8; payload_len as usize];
        self.socket
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read payload: {}", e))?;

        log::debug!(
            "received {:?} message (len={} on={:?} conn={:?})",
            command,
            payload_len,
            self.socket.local_addr().unwrap(),
            self.connection_type,
        );

        Ok((command, payload))
    }

    fn ping(&mut self) -> Result<(), String> {
        // Create ping message as (String, Vec<u8>) instead of RawNetworkMessage
        let ping_payload = vec![0x66, 0x75, 0x7A, 0x7A, 0x08, 0x03, 0x03, 0x03];
        let ping_message = ("ping".to_string(), ping_payload);

        self.send(&ping_message)?;

        loop {
            let received = self.receive()?;
            if received.0 == "pong" {
                break;
            }
        }

        Ok(())
    }

    fn send_and_ping(&mut self, message: &(String, Vec<u8>)) -> Result<(), String> {
        self.send(message)?;
        self.ping()?;
        Ok(())
    }

    fn version_handshake(
        &mut self,
        time: i64,
        relay: bool,
        starting_height: i32,
    ) -> Result<(), String> {
        let socket_addr = self.socket.local_addr().unwrap();

        let mut version_message = VersionMessage::new(
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            time,
            Address::new(&socket_addr, ServiceFlags::NONE),
            Address::new(&socket_addr, ServiceFlags::NONE),
            0xdeadbeef,
            String::from("fuzzamoto"),
            starting_height,
        );

        version_message.version = 70016; // wtxidrelay version
        version_message.relay = relay;

        if self.connection_type == ConnectionType::Outbound {
            loop {
                let received = self.receive()?;
                if received.0 == "version" {
                    break;
                }
            }
        }

        // Convert version message to (String, Vec<u8>) format
        let mut version_bytes = Vec::new();
        version_message
            .consensus_encode(&mut version_bytes)
            .map_err(|e| format!("Failed to encode version message: {}", e))?;
        self.send(&("version".to_string(), version_bytes))?;

        // Send wtxidrelay
        self.send(&("wtxidrelay".to_string(), vec![]))?;

        // Send verack
        self.send(&("verack".to_string(), vec![]))?;

        // Wait for verack
        loop {
            let received = self.receive()?;
            if received.0 == "verack" {
                break;
            }
        }

        Ok(())
    }
}
