pub mod bitcoin_core;
pub use bitcoin_core::BitcoinCoreTarget;

use crate::connections::{Connection, ConnectionType, Transport};

/// `Target` is the interface that the test harness will use to interact with the target Bitcoin
/// implementation (e.g. Bitcoin Core, btcd, etc).
pub trait Target<T: Transport> {
    /// Create a new network connection to the target.
    ///
    /// # Arguments
    ///
    /// * `connection_type` - The type of connection to create (either inbound or outbound)
    fn connect(&mut self, connection_type: ConnectionType) -> Result<Connection<T>, String>;

    /// Set the mocktime for the target.
    ///
    /// This is used to simulate time advancement in the target.
    ///
    /// # Arguments
    ///
    /// * `time` - The new mocktime to set.
    fn set_mocktime(&mut self, time: u64) -> Result<(), String>;

    /// Check if the target is still alive.
    fn is_alive(&self) -> Result<(), String>;
}
