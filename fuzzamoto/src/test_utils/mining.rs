use bitcoin::{
    block,
    blockdata::opcodes::{OP_0, OP_TRUE},
    script::ScriptBuf,
    transaction, Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};

use bitcoin_hashes::sha256;

pub fn mine_block(prev_hash: BlockHash, height: u32, time: u32) -> Result<Block, String> {
    let mut p2wsh_optrue_spk = vec![OP_0.to_u8(), 32];
    let op_true_hash = sha256::Hash::hash(&[OP_TRUE.to_u8()]);
    p2wsh_optrue_spk.extend(op_true_hash.as_byte_array().as_slice());

    // Create a coinbase transaction
    let coinbase = Transaction {
        version: transaction::Version(1),
        lock_time: bitcoin::absolute::LockTime::from_height(0).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::builder()
                .push_int(height as i64)
                .push_int(0xFFFFFFFF)
                .as_script()
                .into(),
            sequence: Sequence(0xFFFFFFFF),
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_int_btc(25),
            script_pubkey: p2wsh_optrue_spk.into(),
        }],
    };

    // Create the block
    let mut block = Block {
        header: block::Header {
            version: block::Version::from_consensus(5),
            prev_blockhash: prev_hash,
            merkle_root: TxMerkleNode::from_raw_hash(*coinbase.txid().as_raw_hash()),
            time,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };

    if cfg!(feature = "reduced_pow") {
        let mut block_hash = block.header.block_hash();
        while block_hash.as_raw_hash()[31] & 0x80 != 0 {
            block.header.nonce += 1;
            block_hash = block.header.block_hash();
        }
    } else {
        // Ensure block meets proof of work requirement
        let target = block.header.target();
        while block.header.validate_pow(target).is_err() {
            block.header.nonce += 1;
        }
    }

    Ok(block)
}
