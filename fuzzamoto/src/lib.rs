pub mod connections;
pub mod dictionaries;
pub mod oracles;
pub mod runners;
pub mod scenarios;
pub mod targets;
pub mod test_utils;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    // TODO: Add things that are needed
    // for example:
    // txids: Vec<usize>
}
