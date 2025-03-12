use crate::{
    connections::{Connection, ConnectionType, V1Transport},
    targets::Target,
};

use corepc_node::{Conf, Node, P2P};
use std::net::{TcpListener, TcpStream};

pub struct BitcoinCoreTarget {
    pub node: Node,
    listeners: Vec<TcpListener>,
}

// Gently stop the node when the target is dropped, if we are not using nyx.
#[cfg(not(feature = "nyx"))]
impl Drop for BitcoinCoreTarget {
    fn drop(&mut self) {
        let _ = self.node.stop();
    }
}

impl BitcoinCoreTarget {
    pub fn new(exe_path: &str) -> Result<Self, String> {
        let mut config = Conf::default();
        config.tmpdir = None;
        config.staticdir = None;
        config.p2p = P2P::Yes;

        #[cfg(feature = "inherit_stdout")]
        {
            config.args.push("-debug");
            config.view_stdout = true;
        }
        config.args.push("-txreconciliation");
        config.args.push("-peerbloomfilters");
        config.args.push("-peerblockfilters");
        config.args.push("-blockfilterindex");
        config.args.push("-par=4");
        config.args.push("-rpcthreads=4");

        let node = Node::with_conf(exe_path, &config)
            .map_err(|e| format!("Failed to start node: {:?}", e))?;

        Ok(Self {
            node,
            listeners: Vec::new(),
        })
    }

    fn create_listener() -> Result<(TcpListener, u16), String> {
        // Bind to port 0 to let the OS assign a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to create TCP listener: {}", e))?;

        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to get listener address: {}", e))?
            .port();

        Ok((listener, port))
    }
}

impl Target<V1Transport> for BitcoinCoreTarget {
    fn connect(
        &mut self,
        connection_type: ConnectionType,
    ) -> Result<Connection<V1Transport>, String> {
        match connection_type {
            ConnectionType::Inbound => {
                // For inbound, connect directly to the P2P port
                let p2p_socket = self
                    .node
                    .params
                    .p2p_socket
                    .ok_or_else(|| "P2P socket address not available".to_string())?;
                let socket = TcpStream::connect(p2p_socket)
                    .map_err(|e| format!("Failed to connect to P2P port: {}", e))?;
                // Disable Nagle's algorithm, since most of the time we're sending small messages and
                // we want to reduce latency when fuzzing.
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on inbound socket");

                Ok(Connection::new(connection_type, V1Transport { socket }))
            }
            ConnectionType::Outbound => {
                let (listener, port) = Self::create_listener()?;
                self.listeners.push(listener);
                let listener = self.listeners.last().unwrap();

                // Tell Bitcoin Core to connect to our listener
                let client = &self.node.client;
                client
                    .call::<serde_json::Value>(
                        "addconnection",
                        &[
                            format!("127.0.0.1:{}", port).into(),
                            "outbound-full-relay".into(),
                            false.into(), // no v2
                        ],
                    )
                    .map_err(|e| format!("Failed to initiate outbound connection: {:?}", e))?;

                // Wait for Bitcoin Core to connect
                let (socket, _addr) = listener
                    .accept()
                    .map_err(|e| format!("Failed to accept connection: {}", e))?;
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on outbound socket");

                Ok(Connection::new(connection_type, V1Transport { socket }))
            }
        }
    }

    fn set_mocktime(&mut self, time: u64) -> Result<(), String> {
        let client = &self.node.client;
        client
            .call::<()>("setmocktime", &[time.into()])
            .map_err(|e| format!("Failed to set mocktime: {:?}", e))
    }

    fn is_alive(&self) -> Result<(), String> {
        // Call the echo rpc to check if the node is still alive
        let client = &self.node.client;
        client
            .call::<serde_json::Value>(
                "echo",
                &[r#"Ground Control to Major Tom
Your circuit's dead, there's something wrong
Can you hear me, Major Tom?
Can you hear me, Major Tom?
Can you hear me, Major Tom?
Can you-"#
                    .into()],
            )
            .map_err(|e| format!("Failed to check if node is alive: {:?}", e))?;

        client
            .call::<()>("syncwithvalidationinterfacequeue", &[])
            .map_err(|e| format!("Failed to sync with validation interface queue: {:?}", e))?;

        Ok(())
    }
}
