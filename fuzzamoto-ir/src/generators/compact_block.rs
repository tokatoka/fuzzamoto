use crate::{
    Instruction, Operation, Variable,
    generators::{Generator, ProgramBuilder},
};
use rand::{Rng, RngCore};

use super::{GeneratorError, GeneratorResult};

/// `CompactFilterQueryGenerator` generates a new `SendGetCFilters`, `SendGetCFHeaders` or
/// `SendGetCFCheckpt` instruction into a global context.
#[derive(Debug, Default)]
pub struct CompactBlockGenerator;

const MAX_TX_SIZE: usize = 32;

impl<R: RngCore> Generator<R> for CompactBlockGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        // choose a block upon which we build the compact block
        let Some(block) = builder.get_random_variable(rng, Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        let connection_var = builder.get_or_create_random_connection(rng);

        let nonce = rng.gen_range(0..u64::MAX);
        let nonce_var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadNonce(nonce),
            })
            .expect("Inserting BeginBuildCmpctBlock should always succeed")
            .pop()
            .expect("BeginBuildCmpctBlock should always produce a var");

        let version = rng.gen_range(1..=2);
        let version_var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadTxVersion(version),
            })
            .expect("Inserting BeginBuildCmpctBlock should always succeed")
            .pop()
            .expect("BeginBuildCmpctBlock should always produce a var");

        let sz = rng.gen_range(0..=MAX_TX_SIZE);
        let mut prefill_vec: Vec<usize> = vec![];
        for _ in 0..sz {
            prefill_vec.push(rng.gen_range(0..=MAX_TX_SIZE));
        }

        // sort it in most cases.
        if rng.gen_bool(0.95) {
            prefill_vec.sort();
        }

        let prefill_var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadPrefill {
                    prefill: prefill_vec,
                },
            })
            .expect("Inserting BeginBuildCmpctBlock should always succeed")
            .pop()
            .expect("BeginBuildCmpctBlock should always produce a var");

        let mut_cmpct_block = builder
            .append(Instruction {
                inputs: vec![
                    block.index,
                    nonce_var.index,
                    version_var.index,
                    prefill_var.index,
                ],
                operation: Operation::BeginBuildCmpctBlock,
            })
            .expect("Inserting BeginBuildCmpctBlock should always succeed")
            .pop()
            .expect("BeginBuildCmpctBlock should always produce a var");

        let cmpct_block = builder
            .append(Instruction {
                inputs: vec![mut_cmpct_block.index],
                operation: Operation::EndBuildCmpctBlock,
            })
            .expect("Inserting EndBuildCmpctBlock should always succeed")
            .pop()
            .expect("EndBuildCmpctBlock should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![connection_var.index, cmpct_block.index],
                operation: Operation::SendCompactBlock,
            })
            .expect("Inserting SendCompactBlock should always succeed");

        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompactBlockGenerator"
    }
}
