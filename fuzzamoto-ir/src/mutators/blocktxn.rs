use super::{Mutator, MutatorError, MutatorResult, Splicer};
use crate::{Program, ProgramBuilder, Operation};
use rand::RngCore;

// `ConcatMutator` takes two programs and concatenates them.
pub struct BlockTxnMutator;

impl<R: RngCore> Mutator<R> for BlockTxnMutator {
    fn mutate(&mut self, program: &mut Program, _rng: &mut R) -> MutatorResult {
        for (_, instruction) in program.instructions.iter().enumerate() {
            match instruction.operation {
                Operation::SendCompactBlock => {
                    let conn = instruction.inputs[0];
                    let cmpct = instruction.inputs[1];
                }
                _ => {
                    // do nothing
                }
            }
        }

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
