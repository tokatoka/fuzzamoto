use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};

use crate::GetBlockTxn;

// The struct to hold the data returned from getblocktxn message.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Hash)]
pub struct BlockTransactionsRequestRecved {
    pub conn: usize,
    pub hash: [u8; 32],
    pub indexes: Vec<u64>,
}

impl BlockTransactionsRequestRecved {
    pub fn new(conn: usize, value: bitcoin::bip152::BlockTransactionsRequest) -> Self {
        Self {
            conn,
            hash: value.block_hash.as_raw_hash().to_byte_array(),
            indexes: value.indexes,
        }
    }

    pub fn conn(&self) -> usize {
        self.conn
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn indexes(&self) -> &[u64] {
        &self.indexes
    }
}

/// The runtime data observed during the course of harness execution
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PerTestcaseMetadata {
    pub block_tx_request: Vec<GetBlockTxn>,
}

impl PerTestcaseMetadata {
    pub fn new() -> Self {
        Self {
            block_tx_request: Vec::new(),
        }
    }

    pub fn block_tx_request(&self) -> &[GetBlockTxn] {
        &self.block_tx_request
    }

    pub fn add_block_tx_request(&mut self, req: GetBlockTxn) {
        // log::info!("We push req: {:?} to the metadata", req.clone());
        self.block_tx_request.push(req);
    }
}
