#[cfg(feature = "nyx")]
use fuzzamoto_nyx_sys::*;

use bitcoin::hashes::Hash;
use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    oracles::{CrashOracle, Oracle, OracleResult},
    scenarios::{
        IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario,
    },
    targets::{BitcoinCoreTarget, HasTipHash, Target},
};
use fuzzamoto_ir::{
    Program, ProgramContext,
    compiler::{CompiledAction, CompiledProgram, Compiler},
};

/// `IrScenario` is a scenario with the same context as `GenericScenario` but it operates on
/// `fuzzamoto_ir::CompiledProgram`s as input.
struct IrScenario<TX: Transport, T: Target<TX>> {
    inner: GenericScenario<TX, T>,
}

pub struct TestCase {
    program: CompiledProgram,
}

impl<'a> ScenarioInput<'a> for TestCase {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let program = if cfg!(feature = "compile_in_vm") {
            let program: Program = postcard::from_bytes(bytes).map_err(|e| e.to_string())?;
            let mut compiler = Compiler::new();
            compiler.compile(&program).map_err(|e| e.to_string())?
        } else {
            postcard::from_bytes(bytes).map_err(|e| e.to_string())?
        };
        Ok(Self { program })
    }
}

impl<TX, T> Scenario<'_, TestCase, IgnoredCharacterization> for IrScenario<TX, T>
where
    TX: Transport,
    T: Target<TX> + HasTipHash,
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner = GenericScenario::new(args)?;

        // Dump program context
        let context = ProgramContext {
            num_nodes: 1,
            num_connections: inner.connections.len(),
            timestamp: inner.time,
        };

        log::info!("IR context: {:?}", context);

        let mut txos: Vec<fuzzamoto_ir::Txo> = Vec::new();
        for (block, _height) in inner
            .block_tree
            .values()
            .filter(|(_, height)| *height < 100)
        {
            let coinbase = block.coinbase().unwrap();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(
                coinbase
                    .compute_txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .as_slice(),
            );

            txos.push(fuzzamoto_ir::Txo {
                outpoint: (hash, 0u32),
                value: 25 * 100_000_000,
                script_pubkey: vec![
                    // 0x0 0x20 sha256(OP_TRUE)
                    0u8, 32, 74, 232, 21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69,
                    67, 46, 131, 225, 85, 30, 111, 114, 30, 233, 192, 11, 140, 195, 50, 96,
                ],
                spending_script_sig: vec![],
                spending_witness: vec![vec![0x51]],
            });
        }

        let headers = inner
            .block_tree
            .values()
            .filter(|(_, height)| *height > 190)
            .map(|(block, height)| fuzzamoto_ir::Header {
                prev: *block.header.prev_blockhash.as_byte_array(),
                merkle_root: *block.header.merkle_root.as_byte_array(),
                nonce: block.header.nonce,
                bits: block.header.bits.to_consensus(),
                time: block.header.time,
                version: block.header.version.to_consensus(),
                height: *height,
            })
            .collect();

        // Dump full program context to host (if using nyx) or to a file if `DUMP_CONTEXT` is set
        let full_context = postcard::to_allocvec(&fuzzamoto_ir::FullProgramContext {
            context,
            txos,
            headers,
        })
        .map_err(|e| e.to_string())?;

        #[cfg(feature = "nyx")]
        {
            let ctx_file_name = "ir.context";
            unsafe {
                nyx_dump_file_to_host(
                    ctx_file_name.as_ptr() as *const i8,
                    ctx_file_name.len(),
                    full_context.as_ptr(),
                    full_context.len(),
                );
            }
        }

        #[cfg(not(feature = "nyx"))]
        if let Ok(context_file) = std::env::var("DUMP_CONTEXT") {
            std::fs::write(context_file, &full_context).map_err(|e| e.to_string())?;
        };

        Ok(Self { inner })
    }

    fn run(&mut self, testcase: TestCase) -> ScenarioResult<IgnoredCharacterization> {
        for action in testcase.program.actions {
            match action {
                CompiledAction::SendRawMessage(from, command, message) => {
                    if self.inner.connections.is_empty() {
                        continue;
                    }

                    let num_connections = self.inner.connections.len();
                    if let Some(connection) = self
                        .inner
                        .connections
                        .get_mut(from as usize % num_connections)
                    {
                        if cfg!(feature = "force_send_and_ping") {
                            let _ = connection.send_and_ping(&(command.to_string(), message));
                        } else {
                            let _ = connection.send(&(command.to_string(), message));
                        }
                    }
                }
                CompiledAction::SetTime(time) => {
                    let _ = self.inner.target.set_mocktime(time);
                }
                _ => {}
            }
        }

        for connection in self.inner.connections.iter_mut() {
            let _ = connection.ping();
        }

        let crash_oracle = CrashOracle::<TX>::default();
        match crash_oracle.evaluate(&self.inner.target) {
            OracleResult::Pass => ScenarioResult::Ok(IgnoredCharacterization),
            OracleResult::Fail(e) => ScenarioResult::Fail(format!("{}", e)),
        }
    }
}

fuzzamoto_main!(
    IrScenario::<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>,
    TestCase
);
