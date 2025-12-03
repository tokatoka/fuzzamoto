use crate::{
    Generator, GeneratorError, GeneratorResult, Instruction, Operation, PerTestcaseMetadata,
    ProgramBuilder, Variable,
};
use rand::RngCore;

/// `BlockTxnGenerator` inserts `blocktxn` operation in response to the `getblocktxn` message
#[derive(Debug, Copy, Clone, Default)]
pub struct BlockTxnGenerator;

impl<R: RngCore> Generator<R> for BlockTxnGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&mut PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let connection_var = builder.get_or_create_random_connection(rng);

        // choose a block upon which we build the blocktxn
        let Some(block) = builder.get_random_variable(rng, Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        let mut_block_txn = builder
            .append(Instruction {
                inputs: vec![block.index],
                operation: Operation::BeginBuildBlockTxn,
            })
            .expect("Inserting BeginBuildBlockTxn should always succeed")
            .pop()
            .expect("BeginBuildBlockTxn should always produce a var");

        let Some(tx) = builder.get_random_variable(rng, Variable::ConstTx) else {
            return Err(GeneratorError::MissingVariables);
        };
        builder
            .append(Instruction {
                inputs: vec![mut_block_txn.index, tx.index],
                operation: Operation::AddTxToBlockTxn,
            })
            .expect("Inserting AddTxToBlockTxn should always suceed");

        let block_txn = builder
            .append(Instruction {
                inputs: vec![mut_block_txn.index],
                operation: Operation::EndBuildBlockTxn,
            })
            .expect("Inserting EndBuildBlockTxn should always succeed")
            .pop()
            .expect("EndBuildBlockTxn should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![connection_var.index, block_txn.index],
                operation: Operation::SendBlockTxn,
            })
            .expect("Inserting SendBlockTxn should always succeed");

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlockTxnGenerator"
    }
}

impl BlockTxnGenerator {
    pub fn new() -> Self {
        Self {}
    }
}
