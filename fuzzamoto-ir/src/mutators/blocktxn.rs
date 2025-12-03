use super::{Mutator, MutatorResult};
use crate::{Instruction, Operation, PerTestcaseMetadata, Program, ProgramBuilder};
use rand::{Rng, RngCore};

/// `BlockTxnMutator` inserts `blocktxn` operation in response to the `getblocktxn` message
#[derive(Debug, Copy, Clone, Default)]
pub struct BlockTxnMutator;

impl<R: RngCore> Mutator<R> for BlockTxnMutator {
    fn mutate(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        meta: Option<&mut PerTestcaseMetadata>,
    ) -> MutatorResult {
        let mut builder = ProgramBuilder::new(program.context.clone());
        let meta = if let Some(meta) = meta {
            meta
        } else {
            // there is nothing to do if metadata is not there.
            return Ok(());
        };
        let insts = program.instructions.clone();

        if insts.is_empty() {
            return Ok(());
        }

        let blocktxn_req = meta.block_tx_request();
        let choice = rng.gen_range(0..blocktxn_req.len());

        // we find the insertion point
        let insertion_point = blocktxn_req[choice].triggering_instruction_index;

        // append the first half
        if !program.instructions.is_empty() {
            let instrs = &program.instructions[..insertion_point];
            builder.append_all(instrs.iter().cloned()).unwrap();
        }
        let variable_threshould = builder.variable_count();

        let block_variable = blocktxn_req[choice].block_variable;
        let mut_block_txn = builder
            .append(Instruction {
                inputs: vec![block_variable],
                operation: Operation::BeginBuildBlockTxn,
            })
            .expect("Inserting BeginBuildBlockTxn should always succeed")
            .pop()
            .expect("BeginBuildBlockTxn should always produce a var");

        for tx in &blocktxn_req[choice].tx_indices_variables {
            builder
                .append(Instruction {
                    inputs: vec![mut_block_txn.index, *tx],
                    operation: Operation::AddTxToBlockTxn,
                })
                .expect("Inserting AddTxToBlockTxn should always suceed");
        }

        let block_txn = builder
            .append(Instruction {
                inputs: vec![mut_block_txn.index],
                operation: Operation::EndBuildBlockTxn,
            })
            .expect("Inserting EndBuildBlockTxn should always succeed")
            .pop()
            .expect("EndBuildBlockTxn should always produce a var");

        let connection = blocktxn_req[choice].connection_index;
        builder
            .append(Instruction {
                inputs: vec![connection, block_txn.index],
                operation: Operation::SendBlockTxn,
            })
            .expect("Inserting SendBlockTxn should always succeed");

        let second_half = Program::unchecked_new(
            builder.context().clone(),
            program.instructions[insertion_point..]
                .iter()
                .cloned()
                .collect(),
        );
        builder
            .append_program(
                second_half,
                variable_threshould,
                builder.variable_count() - variable_threshould,
            )
            .unwrap();
        *program = builder.finalize().unwrap();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlockTxnMutator"
    }
}

impl BlockTxnMutator {
    pub fn new() -> Self {
        Self {}
    }
}
