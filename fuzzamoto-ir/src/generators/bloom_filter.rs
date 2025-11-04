/// `BloomFilterLoadGenerator` generates a new `FilterLoad`, `FilterAdd` or `FilterClear` instruction into a global context.
use crate::{
    CBloomFilter, GeneratorError, IndexedVariable, Instruction, Operation, Variable,
    bloom::{MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS},
    generators::{Generator, ProgramBuilder},
};

use bitcoin::constants::MAX_SCRIPT_ELEMENT_SIZE;
use rand::{Rng, RngCore};

use super::GeneratorResult;

#[derive(Debug, Default)]
pub struct BloomFilterLoadGenerator {
    initial_filter: Option<CBloomFilter>,
}

impl BloomFilterLoadGenerator {
    pub fn new() -> Self {
        Self {
            initial_filter: None,
        }
    }

    pub fn with_filter(filter: CBloomFilter) -> Self {
        Self {
            initial_filter: Some(filter),
        }
    }
}

fn init_filter<R: RngCore>(
    builder: &mut ProgramBuilder,
    initial_filter: &Option<CBloomFilter>,
    rng: &mut R,
) -> Result<IndexedVariable, GeneratorError> {
    let ntweak = rng.gen_range(0..=u32::MAX);
    let nflags = rng.gen_range(0..=2);

    let (bytes, nhash_funcs) = if let Some(x) = &initial_filter {
        let bytes = x.data().to_vec();
        let nhash_funcs = x.n_hash_funcs();

        (bytes, nhash_funcs)
    } else {
        // let size = 0; triggers CVE-2013-5700
        let size = rng.gen_range(0..MAX_BLOOM_FILTER_SIZE) as usize;
        let bytes = vec![0; size];
        let nhash_funcs = rng.gen_range(1..MAX_HASH_FUNCS) as u32;

        (bytes, nhash_funcs)
    };

    let filter_var: crate::IndexedVariable = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadFilterLoad {
                filter: bytes,
                hash_funcs: nhash_funcs,
                tweak: ntweak,
                flags: nflags,
            },
        })
        .expect("Inserting LoadFilterLoad should always succeed")
        .pop()
        .expect("LoadFilterLoad should always produce a var");

    Ok(filter_var)
}

fn populate_filter_from_txdata(
    builder: &mut ProgramBuilder,
    filter_var: IndexedVariable,
    txs: &[IndexedVariable],
    txos: &[IndexedVariable],
) -> Result<IndexedVariable, GeneratorError> {
    // load it first
    let mut_filter_var = builder
        .append(Instruction {
            inputs: vec![filter_var.index],
            operation: Operation::BeginBuildFilterLoad,
        })
        .expect("Inserting BeginBuildFilterLoad should always succeed")
        .pop()
        .expect("BeginBuildFilterLoad should always produce a var");

    // now populate it
    for tx in txs {
        builder
            .append(Instruction {
                inputs: vec![mut_filter_var.index, tx.index],
                operation: Operation::AddTxToFilter,
            })
            .expect("Inserting AddTxToFilter should always succeed");
    }

    for txo in txos {
        builder
            .append(Instruction {
                inputs: vec![mut_filter_var.index, txo.index],
                operation: Operation::AddTxoToFilter,
            })
            .expect("Inserting AddTxoToFilter should always succeed");
    }

    let populated_filter = builder
        .append(Instruction {
            inputs: vec![mut_filter_var.index],
            operation: Operation::EndBuildFilterLoad,
        })
        .expect("Inserting EndBuildFilterLoad should always succeed")
        .pop()
        .expect("EndBuildFilterLoad should always produce a var");

    Ok(populated_filter)
}

impl<R: RngCore> Generator<R> for BloomFilterLoadGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let connection_var = builder.get_or_create_random_connection(rng);

        // we build the filter first.
        // either make a empty filter (but with randomized parameters) or with user-supplied filter
        let filter_var = init_filter(builder, &self.initial_filter, rng)?;

        // next we decide if we put data from existing txdata
        if rng.gen_bool(0.2) {
            let available_txs = builder.get_all_variable(Variable::ConstTx);
            let avaibale_txos = builder.get_all_variable(Variable::Txo);
            let populated =
                populate_filter_from_txdata(builder, filter_var, &available_txs, &avaibale_txos)?;
            // send it because we finished populating
            builder
                .append(Instruction {
                    inputs: vec![connection_var.index, populated.index],
                    operation: Operation::SendFilterLoad,
                })
                .expect("Inserting SendFilterLoad should always succeed");
        } else {
            // just send it off without doing anything
            builder
                .append(Instruction {
                    inputs: vec![connection_var.index, filter_var.index],
                    operation: Operation::SendFilterLoad,
                })
                .expect("Inserting SendFilterLoad should always succeed");
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BloomFilterLoadGenerator"
    }
}

#[derive(Debug, Default)]
pub struct BloomFilterAddGenerator {}

impl<R: RngCore> Generator<R> for BloomFilterAddGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let connection_var = builder.get_or_create_random_connection(rng);
        let filter_loaded = builder.get_nearest_variable(Variable::FilterLoad).is_some();

        if !filter_loaded && rng.gen_bool(0.95) {
            // if we haven't sent filterload message before then early return
            // because if filteradd precedes filterload then it violates the protocol
            return Ok(());
        }

        let choice = rng.gen_range(0..2);
        match choice {
            0 => {
                // send random stuff
                let size = rng.gen_range(0..=MAX_SCRIPT_ELEMENT_SIZE);
                let mut random_bytes = Vec::with_capacity(size);
                rng.fill_bytes(&mut random_bytes);
                // Create the variable for the data first.
                let data_var = builder
                    .append(Instruction {
                        inputs: vec![],
                        operation: Operation::LoadFilterAdd { data: random_bytes },
                    })
                    .expect("Inserting LoadFilterAdd should always succeed")
                    .pop()
                    .expect("LoadFilterAdd should always produce a var");
                // send it off
                builder
                    .append(Instruction {
                        inputs: vec![connection_var.index, data_var.index],
                        operation: Operation::SendFilterAdd,
                    })
                    .expect("Inserting SendFilterAdd should always succeed");
            }
            1 => {
                // use tx
                if let Some(tx) = builder.get_random_variable(rng, Variable::ConstTx) {
                    let filteradd = builder
                        .append(Instruction {
                            inputs: vec![tx.index],
                            operation: Operation::BuildFilterAddFromTx,
                        })
                        .expect("Inserting BuildFilterAddFromTx should always succeed")
                        .pop()
                        .expect("BuildFilterAddFromTx should always produce a var");

                    builder
                        .append(Instruction {
                            inputs: vec![connection_var.index, filteradd.index],
                            operation: Operation::SendFilterAdd,
                        })
                        .expect("Inserting SendFilterAdd should always succeed");
                }
            }
            _ => {
                // use txo
                if let Some(txo) = builder.get_random_variable(rng, Variable::Txo) {
                    let filteradd = builder
                        .append(Instruction {
                            inputs: vec![txo.index],
                            operation: Operation::BuildFilterAddFromTxo,
                        })
                        .expect("Inserting BuildFilterAddFromTx should always succeed")
                        .pop()
                        .expect("BuildFilterAddFromTx should always produce a var");

                    builder
                        .append(Instruction {
                            inputs: vec![connection_var.index, filteradd.index],
                            operation: Operation::SendFilterAdd,
                        })
                        .expect("Inserting SendFilterAdd should always succeed");
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BloomFilterAddGenerator"
    }
}

#[derive(Debug, Default)]
pub struct BloomFilterClearGenerator {}

impl<R: RngCore> Generator<R> for BloomFilterClearGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let connection_var = builder.get_or_create_random_connection(rng);
        builder
            .append(Instruction {
                inputs: vec![connection_var.index],
                operation: Operation::SendFilterClear,
            })
            .expect("Inserting SendFilterClear should always succeed");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "BloomFilterClearGenerator"
    }
}
