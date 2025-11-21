use super::{GeneratorError, GeneratorResult};
use crate::{
    Instruction, Operation, Variable,
    generators::{Generator, ProgramBuilder, compact_block::MAX_TX_SIZE},
};
use rand::{Rng, RngCore};

/// `Blocktxn` generates a new blocktxn message;
#[derive(Debug, Default)]
pub struct BlocktxnGenerator;

impl<R: RngCore> Generator<R> for BlocktxnGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        // choose a block upon which we build the compact block
        let Some(block) = builder.get_random_variable(rng, Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        // just choose a random connection.
        let conn = builder.get_or_create_random_connection(rng);

        let mut indexes_vec: Vec<usize> = vec![];
        for _ in 0..32 {
            indexes_vec.push(rng.gen_range(0..=MAX_TX_SIZE));
        }

        // sort it in most cases.
        if rng.gen_bool(0.95) {
            indexes_vec.sort();
        }

        let indexes_var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadTxIndexes {
                    indexes: indexes_vec,
                },
            })
            .expect("Inserting BeginBuildCmpctBlock should always succeed")
            .pop()
            .expect("BeginBuildCmpctBlock should always produce a var");

        let req = builder
            .append(Instruction {
                inputs: vec![block.index, indexes_var.index],
                operation: Operation::BuildBIP152BlockTxReqFromMetadata,
            })
            .expect("Inserting BuildBIP152BlockTxReqFromMetadata should always succeed")
            .pop()
            .expect("BuildBIP152BlockTxReqFromMetadata should always produce a var");
        builder
            .append(Instruction {
                inputs: vec![conn.index, block.index, req.index],
                operation: Operation::SendBlockTxn,
            })
            .expect("Inserting SendBlockTxn should always succeed");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlocktxnGenerator"
    }
}
