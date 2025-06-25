use std::{any::Any, time::Duration};

use bitcoin::{
    Amount, CompactTarget, EcdsaSighashType, NetworkKind, OutPoint, PrivateKey, Script, ScriptBuf,
    Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, WitnessMerkleNode, Wtxid,
    absolute::LockTime,
    consensus::Encodable,
    ecdsa,
    hashes::{Hash, serde_macros::serde_details::SerdeHash, sha256},
    key::Secp256k1,
    opcodes::{OP_0, OP_TRUE, all::OP_RETURN},
    p2p::{
        message_blockdata::Inventory,
        message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters},
    },
    script::PushBytesBuf,
    secp256k1::{self, SecretKey},
    sighash::SighashCache,
    transaction,
};

use crate::{Instruction, Operation, Program, generators::block::Header};

/// `Compiler` is responsible for compiling IR into a sequence of low-level actions to be performed
/// on a node (i.e. mapping `fuzzamoto_ir::Program` -> `CompiledProgram`).
pub struct Compiler {
    secp_ctx: Secp256k1<bitcoin::secp256k1::All>,

    variables: Vec<Box<dyn Any>>,
    output: CompiledProgram,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum CompiledAction {
    /// Create a new connection
    Connect(usize, String),
    /// Send a message on one of the connections
    SendRawMessage(usize, String, Vec<u8>),
    /// Set mock time for all nodes in the test
    SetTime(u64),

    /// Probe state of the nodes under test to enable smarter mutations
    Probe(Probe),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum Probe {
    /// Probe for mempool contents
    Mempool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CompiledProgram {
    pub actions: Vec<CompiledAction>,
}

#[derive(Debug)]
pub enum CompilerError {
    MiscError(String),
    IncorrectNumberOfInputs,
    VariableNotFound,
    IncorrectVariableType,
}

impl std::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompilerError::MiscError(e) => write!(f, "Misc error: {}", e),
            CompilerError::IncorrectNumberOfInputs => write!(f, "Incorrect number of inputs"),
            CompilerError::VariableNotFound => write!(f, "Variable not found"),
            CompilerError::IncorrectVariableType => write!(f, "Incorrect variable type"),
        }
    }
}

pub type CompilerResult = Result<CompiledProgram, CompilerError>;

#[derive(Clone, Debug)]
struct Scripts {
    script_pubkey: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Witness,

    // op & vars
    requires_signing: Option<(Operation, Vec<usize>)>,
}

#[derive(Debug, Clone)]
struct Witness {
    stack: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct Txo {
    prev_out: ([u8; 32], u32),
    scripts: Scripts,
    value: u64,
}

#[derive(Clone)]
struct TxOutputs {
    outputs: Vec<(Scripts, u64)>,
    fees: u64,
}

#[derive(Clone)]
struct TxInput {
    txo_var: usize,
    sequence_var: usize,
}

#[derive(Clone)]
struct TxInputs {
    inputs: Vec<TxInput>,
    total_value: u64,
}

#[derive(Clone, Debug)]
struct Tx {
    tx: Transaction,
    txos: Vec<Txo>,
    output_selector: usize,
}

struct Nop;

impl Compiler {
    pub fn compile(&mut self, ir: &Program) -> CompilerResult {
        for instruction in &ir.instructions {
            match instruction.operation.clone() {
                Operation::Nop {
                    outputs,
                    inner_outputs,
                } => {
                    for _ in 0..outputs {
                        self.append_variable(Nop);
                    }
                    for _ in 0..inner_outputs {
                        self.append_variable(Nop);
                    }
                }
                Operation::LoadNode(index) => {
                    self.append_variable(index);
                }
                Operation::LoadConnection(index) => {
                    self.append_variable(index);
                }
                Operation::LoadConnectionType(connection_type) => {
                    self.append_variable(connection_type);
                }
                Operation::LoadDuration(duration) => {
                    self.append_variable(duration);
                }
                Operation::LoadAmount(amount) => {
                    self.append_variable(amount);
                }
                Operation::LoadTxVersion(version) => {
                    self.append_variable(version);
                }
                Operation::LoadBlockVersion(version) => {
                    self.append_variable(version);
                }
                Operation::LoadHeader {
                    prev,
                    merkle_root,
                    nonce,
                    bits,
                    time,
                    version,
                    height,
                } => {
                    self.append_variable(Header {
                        prev,
                        merkle_root,
                        nonce,
                        bits,
                        time,
                        version,
                        height,
                    });
                }
                Operation::LoadLockTime(lock_time) => {
                    self.append_variable(lock_time);
                }
                Operation::LoadSequence(sequence) => {
                    self.append_variable(sequence);
                }
                Operation::LoadTime(time) => {
                    self.append_variable(time);
                }
                Operation::LoadBlockHeight(height) => {
                    self.append_variable(height);
                }
                Operation::LoadCompactFilterType(filter_type) => {
                    self.append_variable(filter_type);
                }
                Operation::LoadMsgType(message_type) => {
                    self.append_variable(message_type);
                }
                Operation::LoadBytes(bytes) => {
                    self.append_variable(bytes);
                }
                Operation::LoadSize(size) => {
                    self.append_variable(size);
                }
                Operation::LoadPrivateKey(private_key) => {
                    self.append_variable(private_key);
                }
                Operation::LoadSigHashFlags(sig_hash_flags) => {
                    self.append_variable(sig_hash_flags);
                }
                Operation::LoadTxo {
                    outpoint,
                    value,
                    script_pubkey,
                    spending_script_sig,
                    spending_witness,
                } => {
                    self.append_variable(Txo {
                        prev_out: outpoint,
                        value,
                        scripts: Scripts {
                            script_pubkey,
                            script_sig: spending_script_sig,
                            witness: Witness {
                                stack: spending_witness,
                            },
                            requires_signing: None,
                        },
                    });
                }

                Operation::BeginBlockTransactions => {
                    self.append_variable(Vec::<Tx>::new());
                }

                Operation::AddTx => {
                    let tx_var = self.get_nth_variable::<Tx>(&instruction.inputs, 1)?.clone();
                    let block_transactions_var =
                        self.get_nth_variable_mut::<Vec<Tx>>(&instruction.inputs, 0)?;
                    block_transactions_var.push(tx_var);
                }

                Operation::EndBlockTransactions => {
                    let block_transactions_var =
                        self.get_nth_variable::<Vec<Tx>>(&instruction.inputs, 0)?;
                    self.append_variable(block_transactions_var.clone());
                }

                Operation::BuildBlock => self.build_block(&instruction)?,

                Operation::BeginBuildInventory => {
                    self.append_variable(Vec::<Inventory>::new());
                }

                Operation::EndBuildInventory => {
                    let bytes_var = self
                        .get_nth_variable::<Vec<Inventory>>(&instruction.inputs, 0)?
                        .clone();
                    self.append_variable(bytes_var.clone());
                }

                Operation::AddTxidWithWitnessInv => {
                    let tx_var = self.get_nth_variable::<Tx>(&instruction.inputs, 1)?;
                    let inv = Inventory::WitnessTransaction(tx_var.tx.compute_txid());
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }

                Operation::AddWtxidInv => {
                    let tx_var = self.get_nth_variable::<Tx>(&instruction.inputs, 1)?;
                    let inv = Inventory::WTx(tx_var.tx.compute_wtxid());
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }

                Operation::AddTxidInv => {
                    let tx_var = self.get_nth_variable::<Tx>(&instruction.inputs, 1)?;
                    let inv = Inventory::Transaction(tx_var.tx.compute_txid());
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }

                Operation::AddBlockInv => {
                    let block_var =
                        self.get_nth_variable::<bitcoin::Block>(&instruction.inputs, 1)?;
                    let inv = Inventory::Block(block_var.header.block_hash());
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }
                Operation::AddBlockWithWitnessInv => {
                    let block_var =
                        self.get_nth_variable::<bitcoin::Block>(&instruction.inputs, 1)?;
                    let inv = Inventory::WitnessBlock(block_var.header.block_hash());
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }
                Operation::AddFilteredBlockInv => {
                    let block_var =
                        self.get_nth_variable::<bitcoin::Block>(&instruction.inputs, 1)?;
                    let inv = Inventory::Unknown {
                        inv_type: 3, // MSG_FILTERED_BLOCK, see Bitcoin Core
                        hash: *block_var.header.block_hash().as_byte_array(),
                    };
                    let inventory_var =
                        self.get_nth_variable_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                    inventory_var.push(inv);
                }

                Operation::BeginWitnessStack => {
                    self.append_variable(Witness { stack: Vec::new() });
                }
                Operation::AddWitness => {
                    let bytes_var = self
                        .get_nth_variable::<Vec<u8>>(&instruction.inputs, 1)?
                        .clone();
                    let witness_var =
                        self.get_nth_variable_mut::<Witness>(&instruction.inputs, 0)?;

                    witness_var.stack.push(bytes_var);
                }
                Operation::EndWitnessStack => {
                    let witness_var = self.get_nth_variable::<Witness>(&instruction.inputs, 0)?;
                    self.append_variable(witness_var.clone());
                }

                Operation::BuildPayToWitnessScriptHash => {
                    let script = self.get_nth_variable::<Vec<u8>>(&instruction.inputs, 0)?;
                    let witness_var = self.get_nth_variable::<Witness>(&instruction.inputs, 1)?;

                    let mut witness = witness_var.clone();
                    witness.stack.push(script.clone());

                    // OP_0 0x20 <script hash>
                    let mut script_pubkey = vec![OP_0.to_u8(), 32];
                    let script_hash = sha256::Hash::hash(script.as_slice());
                    script_pubkey.extend(script_hash.as_byte_array().as_slice());

                    self.append_variable(Scripts {
                        script_pubkey,
                        script_sig: vec![],
                        witness,
                        requires_signing: None,
                    });
                }
                Operation::BuildPayToScriptHash => {
                    let script = self.get_nth_variable::<Vec<u8>>(&instruction.inputs, 0)?;
                    let witness_var = self.get_nth_variable::<Witness>(&instruction.inputs, 1)?;

                    let mut witness = witness_var.clone();
                    witness.stack.push(script.clone());

                    let mut script_sig_builder = ScriptBuf::builder().push_opcode(OP_0);
                    for elem in witness.stack.drain(..) {
                        script_sig_builder =
                            script_sig_builder.push_slice(&PushBytesBuf::try_from(elem).unwrap());
                    }

                    let script_hash = ScriptBuf::from(script.clone()).script_hash();
                    let script_pubkey = ScriptBuf::new_p2sh(&script_hash).into_bytes();

                    self.append_variable(Scripts {
                        script_pubkey,
                        script_sig: script_sig_builder.into_bytes(),
                        witness: Witness { stack: Vec::new() },
                        requires_signing: None,
                    });
                }
                Operation::BuildPayToAnchor => {
                    self.append_variable(Scripts {
                        script_pubkey: vec![OP_TRUE.to_u8(), 0x2, 0x4e, 0x73], // P2A: https://github.com/bitcoin/bitcoin/pull/30352
                        script_sig: vec![],
                        witness: Witness { stack: Vec::new() },
                        requires_signing: None,
                    });
                }

                Operation::BuildRawScripts => {
                    let script_pubkey_var =
                        self.get_nth_variable::<Vec<u8>>(&instruction.inputs, 0)?;
                    let script_sig_var =
                        self.get_nth_variable::<Vec<u8>>(&instruction.inputs, 1)?;
                    let witness_var = self.get_nth_variable::<Witness>(&instruction.inputs, 2)?;

                    let script_pubkey = script_pubkey_var.clone();
                    let script_sig = script_sig_var.clone();
                    let witness = witness_var.clone();

                    self.append_variable(Scripts {
                        script_pubkey,
                        script_sig,
                        witness,
                        requires_signing: None,
                    });
                }

                Operation::BuildOpReturnScripts => {
                    let size_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;

                    let data = vec![0x41u8; *size_var];
                    let script = ScriptBuf::builder()
                        .push_opcode(OP_RETURN)
                        .push_slice(&PushBytesBuf::try_from(data).unwrap());

                    self.append_variable(Scripts {
                        script_pubkey: script.into_bytes(),
                        script_sig: vec![],
                        witness: Witness { stack: Vec::new() },
                        requires_signing: None,
                    });
                }

                Operation::BuildPayToPubKey
                | Operation::BuildPayToPubKeyHash
                | Operation::BuildPayToWitnessPubKeyHash => {
                    let private_key_var =
                        self.get_nth_variable::<[u8; 32]>(&instruction.inputs, 0)?;
                    let _sig_hash_flags_var =
                        self.get_nth_variable::<u8>(&instruction.inputs, 1)?;

                    let private_key =
                        PrivateKey::from_slice(private_key_var, NetworkKind::Main).unwrap();
                    let public_key = private_key.public_key(&self.secp_ctx);
                    let public_key_bytes = public_key.to_bytes();

                    let (script_pubkey, script_sig, witness_stack) = match &instruction.operation {
                        Operation::BuildPayToPubKey => {
                            (ScriptBuf::new_p2pk(&public_key), ScriptBuf::new(), vec![])
                        }
                        Operation::BuildPayToPubKeyHash => (
                            ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
                            ScriptBuf::builder().push_key(&public_key).into_script(),
                            vec![],
                        ),
                        Operation::BuildPayToWitnessPubKeyHash => (
                            ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()),
                            ScriptBuf::new(),
                            vec![public_key_bytes],
                        ),
                        _ => (ScriptBuf::new(), ScriptBuf::new(), vec![]),
                    };

                    self.append_variable(Scripts {
                        script_pubkey: script_pubkey.into(),
                        script_sig: script_sig.into(),
                        witness: Witness {
                            stack: witness_stack,
                        },
                        requires_signing: Some((
                            instruction.operation.clone(),
                            vec![instruction.inputs[0], instruction.inputs[1]],
                        )),
                    });
                }

                Operation::BeginBuildTx => {
                    let tx_version_var = self.get_nth_variable::<u32>(&instruction.inputs, 0)?;
                    let tx_lock_time_var = self.get_nth_variable::<u32>(&instruction.inputs, 1)?;

                    self.append_variable(Tx {
                        tx: Transaction {
                            version: transaction::Version(*tx_version_var as i32),
                            lock_time: LockTime::from_consensus(*tx_lock_time_var),
                            input: Vec::new(),
                            output: Vec::new(),
                        },
                        txos: Vec::new(),
                        output_selector: 0,
                    });
                }
                Operation::EndBuildTx => self.finalize_tx(&instruction)?,

                Operation::BeginBuildTxInputs => {
                    self.append_variable(TxInputs {
                        inputs: Vec::new(),
                        total_value: 0,
                    });
                }
                Operation::EndBuildTxInputs => {
                    let tx_inputs_var =
                        self.get_nth_variable::<TxInputs>(&instruction.inputs, 0)?;
                    self.append_variable(tx_inputs_var.clone());
                }

                Operation::AddTxInput => self.add_tx_input(&instruction)?,

                Operation::BeginBuildTxOutputs => {
                    let tx_inputs_var =
                        self.get_nth_variable::<TxInputs>(&instruction.inputs, 0)?;
                    let fees = tx_inputs_var.total_value;
                    self.append_variable(TxOutputs {
                        outputs: Vec::new(),
                        fees,
                    });
                }
                Operation::EndBuildTxOutputs => {
                    let tx_outputs_var = self
                        .get_nth_variable_mut::<TxOutputs>(&instruction.inputs, 0)?
                        .clone();
                    self.append_variable(tx_outputs_var);
                }

                Operation::AddTxOutput => {
                    let scripts = self
                        .get_nth_variable::<Scripts>(&instruction.inputs, 1)?
                        .clone();
                    let amount = self
                        .get_nth_variable::<u64>(&instruction.inputs, 2)?
                        .clone();

                    let mut_tx_outputs_var =
                        self.get_nth_variable_mut::<TxOutputs>(&instruction.inputs, 0)?;

                    let amount = amount.min(mut_tx_outputs_var.fees);
                    mut_tx_outputs_var.outputs.push((scripts, amount));
                    mut_tx_outputs_var.fees -= amount;
                }

                Operation::AdvanceTime => {
                    let time_var = self.get_nth_variable::<u64>(&instruction.inputs, 0)?;
                    let duration_var = self.get_nth_variable::<Duration>(&instruction.inputs, 1)?;

                    self.append_variable(*time_var + duration_var.as_secs());
                }

                Operation::SetTime => {
                    let time_var = self.get_nth_variable::<u64>(&instruction.inputs, 0)?;
                    self.output.actions.push(CompiledAction::SetTime(*time_var));
                }

                Operation::TakeTxo => {
                    let txo = {
                        let tx_var = self.get_nth_variable_mut::<Tx>(&instruction.inputs, 0)?;
                        tx_var.output_selector += 1; // TODO: wrap around?
                        tx_var.txos[tx_var.output_selector - 1].clone()
                    };

                    self.append_variable(txo);
                }

                Operation::SendRawMessage => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let message_type_var =
                        self.get_nth_variable::<[char; 12]>(&instruction.inputs, 1)?;
                    let bytes_var = self.get_nth_variable::<Vec<u8>>(&instruction.inputs, 2)?;

                    self.emit_send_raw_message(
                        *connection_var,
                        &message_type_var.iter().collect::<String>(),
                        bytes_var.clone(),
                    );
                }

                Operation::SendTxNoWit | Operation::SendTx => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let tx_var = self.get_nth_variable::<Tx>(&instruction.inputs, 1)?;

                    let mut tx_var = tx_var.clone();
                    if matches!(instruction.operation, Operation::SendTxNoWit) {
                        for input in tx_var.tx.input.iter_mut() {
                            input.witness.clear();
                        }
                    }

                    self.emit_send_message(*connection_var, "tx", &tx_var.tx);
                }
                Operation::SendGetData | Operation::SendInv => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let inv_var =
                        self.get_nth_variable::<Vec<Inventory>>(&instruction.inputs, 1)?;

                    let msg_type = if matches!(instruction.operation, Operation::SendInv) {
                        "inv"
                    } else {
                        "getdata"
                    };

                    self.emit_send_raw_message(
                        *connection_var,
                        msg_type,
                        bitcoin::consensus::encode::serialize(&inv_var),
                    );
                }

                Operation::SendHeader => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let header_var = self.get_nth_variable::<Header>(&instruction.inputs, 1)?;

                    let mut data = vec![1u8]; // 1 header
                    data.extend(bitcoin::consensus::encode::serialize(
                        &header_var.to_bitcoin_header(),
                    ));
                    data.push(0); // empty txdata

                    self.emit_send_raw_message(*connection_var, "headers", data);
                }
                Operation::SendBlock | Operation::SendBlockNoWit => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let block_var =
                        self.get_nth_variable::<bitcoin::Block>(&instruction.inputs, 1)?;

                    let mut block_var = block_var.clone();
                    if matches!(instruction.operation, Operation::SendBlockNoWit) {
                        for tx in block_var.txdata.iter_mut() {
                            for input in tx.input.iter_mut() {
                                input.witness.clear();
                            }
                        }
                    }
                    self.emit_send_message(*connection_var, "block", &block_var);
                }
                Operation::SendGetCFilters | Operation::SendGetCFHeaders => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let compact_filter_type_var =
                        self.get_nth_variable::<u8>(&instruction.inputs, 1)?;
                    let block_height_var = self.get_nth_variable::<u32>(&instruction.inputs, 2)?;
                    let header_var = self.get_nth_variable::<Header>(&instruction.inputs, 3)?;

                    if matches!(instruction.operation, Operation::SendGetCFilters) {
                        self.emit_send_message(
                            *connection_var,
                            "getcfilters",
                            &GetCFilters {
                                filter_type: *compact_filter_type_var,
                                start_height: *block_height_var,
                                stop_hash: header_var.to_bitcoin_header().block_hash(),
                            },
                        );
                    } else {
                        self.emit_send_message(
                            *connection_var,
                            "getcfheaders",
                            &GetCFHeaders {
                                filter_type: *compact_filter_type_var,
                                start_height: *block_height_var,
                                stop_hash: header_var.to_bitcoin_header().block_hash(),
                            },
                        );
                    };
                }
                Operation::SendGetCFCheckpt => {
                    let connection_var = self.get_nth_variable::<usize>(&instruction.inputs, 0)?;
                    let compact_filter_type_var =
                        self.get_nth_variable::<u8>(&instruction.inputs, 1)?;
                    let header_var = self.get_nth_variable::<Header>(&instruction.inputs, 2)?;

                    self.emit_send_message(
                        *connection_var,
                        "getcfcheckpt",
                        &GetCFCheckpt {
                            filter_type: *compact_filter_type_var,
                            stop_hash: header_var.to_bitcoin_header().block_hash(),
                        },
                    );
                }
            }
        }

        Ok(self.output.clone()) // TODO: do not clone
    }

    pub fn new() -> Self {
        Self {
            // TODO: make this deterministic
            secp_ctx: Secp256k1::new(),
            variables: Vec::with_capacity(4096),
            output: CompiledProgram {
                actions: Vec::with_capacity(4096),
            },
        }
    }

    fn get_variable<'a, T: 'static>(&'a self, index: usize) -> Result<&'a T, CompilerError> {
        let var = self
            .variables
            .get(index)
            .ok_or(CompilerError::VariableNotFound)?;
        let var = var
            .downcast_ref::<T>()
            .ok_or(CompilerError::IncorrectVariableType)?;
        Ok(var)
    }

    fn get_nth_variable<'a, T: 'static>(
        &'a self,
        inputs: &[usize],
        index: usize,
    ) -> Result<&'a T, CompilerError> {
        let var_index = inputs
            .get(index)
            .ok_or(CompilerError::IncorrectNumberOfInputs)?;
        let var = self
            .variables
            .get(*var_index)
            .ok_or(CompilerError::VariableNotFound)?;
        let var = var
            .downcast_ref::<T>()
            .ok_or(CompilerError::IncorrectVariableType)?;
        Ok(var)
    }

    fn get_nth_variable_mut<'a, T: 'static>(
        &'a mut self,
        inputs: &[usize],
        index: usize,
    ) -> Result<&'a mut T, CompilerError> {
        let var_index = inputs
            .get(index)
            .ok_or(CompilerError::IncorrectNumberOfInputs)?;
        let var = self
            .variables
            .get_mut(*var_index)
            .ok_or(CompilerError::VariableNotFound)?;
        let var = var
            .downcast_mut::<T>()
            .ok_or(CompilerError::IncorrectVariableType)?;
        Ok(var)
    }

    fn append_variable<T: 'static>(&mut self, value: T) {
        self.variables.push(Box::new(value));
    }

    fn emit_send_raw_message(&mut self, connection_var: usize, message_type: &str, bytes: Vec<u8>) {
        self.output.actions.push(CompiledAction::SendRawMessage(
            connection_var,
            message_type.to_string(),
            bytes,
        ));
    }

    fn emit_send_message<T: Encodable>(
        &mut self,
        connection_var: usize,
        message_type: &str,
        message: &T,
    ) {
        self.emit_send_raw_message(
            connection_var,
            message_type,
            bitcoin::consensus::encode::serialize(message),
        );
    }

    fn build_block(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let header_var = self.get_nth_variable::<Header>(&instruction.inputs, 0)?;
        let time_var = self.get_nth_variable::<u64>(&instruction.inputs, 1)?;
        let block_version_var = self.get_nth_variable::<i32>(&instruction.inputs, 2)?;
        let block_transactions_var = self.get_nth_variable::<Vec<Tx>>(&instruction.inputs, 3)?;

        let mut witness = bitcoin::Witness::new();
        witness.push([0u8; 32]);
        let mut txdata = vec![Transaction {
            version: transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::from_height(0).unwrap(),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::builder()
                    .push_int((header_var.height + 1) as i64)
                    .push_int(0xFFFFFFFF)
                    .as_script()
                    .into(),
                sequence: Sequence(0xFFFFFFFF),
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_int_btc(25),
                    script_pubkey: vec![].into(), // TODO
                },
                fuzzamoto::test_utils::mining::create_witness_commitment_output(
                    WitnessMerkleNode::from_raw_hash(Wtxid::all_zeros().into()),
                ),
            ],
        }];
        txdata.extend(block_transactions_var.iter().map(|tx| tx.tx.clone()));

        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(*block_version_var),
                prev_blockhash: header_var.to_bitcoin_header().block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                bits: CompactTarget::from_consensus(header_var.bits),
                nonce: header_var.nonce,
                time: *time_var as u32,
            },
            txdata,
        };
        fuzzamoto::test_utils::mining::fixup_commitments(&mut block);

        if cfg!(feature = "reduced_pow") {
            let mut block_hash = block.header.block_hash();
            while block_hash.as_raw_hash()[31] & 0x80 != 0 {
                block.header.nonce += 1;
                block_hash = block.header.block_hash();
            }
            log::info!("{:?} height={}", block_hash, header_var.height);
        } else {
            let target = block.header.target();
            while block.header.validate_pow(target).is_err() {
                block.header.nonce += 1;
            }
        }

        self.append_variable(Header {
            prev: *block.header.prev_blockhash.as_byte_array(),
            merkle_root: *block.header.merkle_root.as_byte_array(),
            bits: block.header.bits.to_consensus(),
            time: block.header.time,
            height: header_var.height + 1,
            nonce: block.header.nonce,
            version: block.header.version.to_consensus(),
        });

        self.append_variable(block);

        Ok(())
    }

    fn add_tx_input(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let txo_var = self.get_nth_variable::<Txo>(&instruction.inputs, 1)?;
        let _sequence_var = self.get_nth_variable::<u32>(&instruction.inputs, 2)?;

        let value = txo_var.value;
        let mut_tx_inputs_var = self.get_nth_variable_mut::<TxInputs>(&instruction.inputs, 0)?;

        mut_tx_inputs_var.inputs.push(TxInput {
            txo_var: instruction.inputs[1],
            sequence_var: instruction.inputs[2],
        });
        mut_tx_inputs_var.total_value += value;
        Ok(())
    }

    fn finalize_tx(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let tx_inputs_var = self
            .get_nth_variable::<TxInputs>(&instruction.inputs, 1)?
            .clone();
        let tx_outputs_var = self
            .get_nth_variable::<TxOutputs>(&instruction.inputs, 2)?
            .clone();
        let mut tx_var = self
            .get_nth_variable_mut::<Tx>(&instruction.inputs, 0)?
            .clone();

        // Fill in the inputs and outputs
        tx_var
            .tx
            .input
            .extend(tx_inputs_var.inputs.iter().map(|tx_input| {
                let txo_var = self.get_variable::<Txo>(tx_input.txo_var).unwrap();
                let sequence_var = self.get_variable::<u32>(tx_input.sequence_var).unwrap();
                TxIn {
                    previous_output: OutPoint::new(
                        Txid::from_slice_delegated(&txo_var.prev_out.0).unwrap(),
                        txo_var.prev_out.1,
                    ),
                    script_sig: Script::from_bytes(&txo_var.scripts.script_sig).into(),
                    witness: bitcoin::Witness::from(txo_var.scripts.witness.stack.as_slice()),
                    sequence: Sequence(*sequence_var),
                }
            }));

        tx_var.tx.output.extend(
            tx_outputs_var
                .outputs
                .iter()
                .map(|(scripts, amount)| TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: Script::from_bytes(scripts.script_pubkey.as_slice()).into(),
                }),
        );

        // Sign inputs
        for (idx, input) in tx_inputs_var.inputs.iter().enumerate() {
            let txo_var = self.get_variable::<Txo>(input.txo_var).unwrap();
            if let Some((operation, input_indices)) = &txo_var.scripts.requires_signing {
                let private_key = *self.get_variable::<[u8; 32]>(input_indices[0]).unwrap();
                let sighash_flag = *self.get_variable::<u8>(input_indices[1]).unwrap();

                let mut cache = SighashCache::new(&tx_var.tx);

                match operation {
                    Operation::BuildPayToPubKey | Operation::BuildPayToPubKeyHash => {
                        if let Ok(hash) = cache.legacy_signature_hash(
                            idx,
                            Script::from_bytes(&txo_var.scripts.script_pubkey),
                            sighash_flag as u32,
                        ) {
                            let signature = ecdsa::Signature {
                                signature: self.secp_ctx.sign_ecdsa(
                                    &secp256k1::Message::from_digest(*hash.as_byte_array()),
                                    &SecretKey::from_slice(private_key.as_slice()).unwrap(),
                                ),
                                sighash_type: EcdsaSighashType::from_consensus(sighash_flag as u32),
                            };

                            tx_var.tx.input[idx]
                                .script_sig
                                .push_slice(PushBytesBuf::try_from(signature.to_vec()).unwrap());
                        }
                    }
                    Operation::BuildPayToWitnessPubKeyHash => {
                        let sighash_type = EcdsaSighashType::from_consensus(sighash_flag as u32);
                        if let Ok(hash) = cache.p2wpkh_signature_hash(
                            idx,
                            Script::from_bytes(&txo_var.scripts.script_pubkey),
                            Amount::from_sat(txo_var.value),
                            sighash_type,
                        ) {
                            let signature = ecdsa::Signature {
                                signature: self.secp_ctx.sign_ecdsa(
                                    &secp256k1::Message::from_digest(*hash.as_byte_array()),
                                    &SecretKey::from_slice(private_key.as_slice()).unwrap(),
                                ),
                                sighash_type,
                            };

                            tx_var.tx.input[idx].witness.push(signature.to_vec());
                        }
                    }

                    _ => {}
                }
            }
        }

        let txid = *tx_var.tx.compute_txid().as_raw_hash().as_byte_array();

        // Create all `Txo`s for this transaction and store them on the new finalized tx var
        tx_var.txos = tx_outputs_var
            .outputs
            .iter()
            .enumerate()
            .map(|(index, (scripts, amount))| Txo {
                prev_out: (txid, index as u32),
                scripts: scripts.clone(),
                value: *amount,
            })
            .collect();

        self.append_variable(tx_var);

        Ok(())
    }
}
