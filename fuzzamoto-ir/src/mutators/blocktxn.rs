use super::{Mutator, MutatorError, MutatorResult};
use crate::{Instruction, Operation, PerTestcaseMetadata, Program, ProgramBuilder};
use rand::RngCore;

/// `BlockTxn` inserts `blocktxn` operation in response to the `getblocktxn` message
pub struct BlockTxnMutator;

impl<R: RngCore> Mutator<R> for BlockTxnMutator {
    fn mutate(
        &mut self,
        program: &mut Program,
        _rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> MutatorResult {
        let mut builder = ProgramBuilder::new(program.context.clone());
        let meta = if let Some(meta) = meta {
            meta
        } else {
            // there is nothing to do if metadata is not there.
            return Ok(());
        };
        let mut i = 0;
        let insts = program.instructions.clone();
        while i < insts.len() {
            // check if we have room for i+3
            if i + 3 < insts.len()
                && matches!(insts[i].operation, Operation::BeginBuildCmpctBlock)
                && matches!(insts[i + 1].operation, Operation::EndBuildCmpctBlock)
                && matches!(insts[i + 2].operation, Operation::SendCompactBlock)
                && !matches!(
                    &insts[i + 3].operation,
                    Operation::LoadBlockTxnRequestVec { vec: _ }
                )
            {
                // push exsisting ones
                builder
                    .append(insts[i].clone())
                    .expect("Inserting an existing instruction should always succeed");
                builder
                    .append(insts[i + 1].clone())
                    .expect("Inserting an existing instruction should always succeed");
                builder
                    .append(insts[i + 2].clone())
                    .expect("Inserting an existing instruction should always succeed");

                // get it from `Operation::SendCompactBlock`
                let conn = insts[i + 2].inputs[0];
                // get it from `Operation::BeginBuildCmpctBlock`
                let block = insts[i].inputs[0];

                let reqvec = builder
                    .append(Instruction {
                        inputs: vec![],
                        operation: Operation::LoadBlockTxnRequestVec {
                            vec: meta.block_tx_request().to_vec(),
                        },
                    })
                    .expect("Inserting LoadBlockTxnRequestVec should always succeed")
                    .pop()
                    .expect("LoadBlockTxnRequestVec should always produce a var");
                builder
                    .append(Instruction {
                        inputs: vec![conn, block, reqvec.index],
                        operation: Operation::BuildBIP152BlockTxReq,
                    })
                    .expect("Inserting BuildBIP152BlockTxReq should always succeed");
                i += 3;

                continue;
            } else {
                builder
                    .append(insts[i].clone())
                    .expect("Inserting an existing instruction should always succeed");
                // default case: just copy the current instruction
                i += 1;
            }
        }
        *program = builder
            .finalize()
            .map_err(|_| MutatorError::CreatedInvalidProgram)?;
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
