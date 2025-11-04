/// `BloomFilterGenerator` generates a new `FilterLoad`, `FilterAdd` or `FilterClear` instruction into a global context.
use crate::{
    Instruction, Operation, Variable,
    generators::{Generator, ProgramBuilder},
};
use rand::{Rng, RngCore, seq::SliceRandom};

use super::GeneratorResult;

#[derive(Debug, Default)]
pub struct BloomFilterGenerator;

// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki?plain=1#L72
/// Maximum size for filteradd data
const FILTERADD_MAX: usize = 520;

// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki?plain=1#L51
/// Maximum size for filterload filter
const FILTERLOAD_FILTER_MAX: usize = 36000;
const FILTERLOAD_NHASH_MAX: usize = 50;

impl<R: RngCore> Generator<R> for BloomFilterGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        // check if we already sent a `filterload` message
        // if we have sent `Operation::SendFilterLoad` message already, then by now we've loaded a
        let filter_loaded = match builder.get_nearest_variable(Variable::FilterLoad) {
            Some(_) => true,
            None => false,
        };

        let mut ops = Vec::from([Operation::SendFilterLoad, Operation::SendFilterClear]);
        if filter_loaded {
            // we cannot send `filteradd` before sending at least one `filterload` else the node will treat us as "misbehaving".
            ops.push(Operation::SendFilterAdd)
        }

        let connection_var = builder.get_or_create_random_connection(rng);

        let op = ops.choose(rng).unwrap().clone();
        match op {
            Operation::SendFilterLoad => {
                let mut random_bytes = Vec::new();
                let size = rng.gen_range(1..FILTERLOAD_FILTER_MAX);
                random_bytes.resize(size, 0);
                rng.fill_bytes(&mut random_bytes);

                let nhash_funcs = rng.gen_range(1..FILTERLOAD_NHASH_MAX) as u32;
                let ntweak = rng.gen_range(0..=u32::MAX);
                let nflags = rng.gen_range(0..=2);
                let filter_var = builder
                    .append(Instruction {
                        inputs: vec![],
                        operation: Operation::LoadFilterLoad {
                            filter: random_bytes,
                            hash_funcs: nhash_funcs,
                            tweak: ntweak,
                            flags: nflags,
                        },
                    })
                    .expect("Inserting LoadFilterLoad should always succeed")
                    .pop()
                    .expect("LoadFilterLoad should always produce a var");

                builder
                    .append(Instruction {
                        inputs: vec![connection_var.index, filter_var.index],
                        operation: Operation::SendFilterLoad,
                    })
                    .expect("Inserting SendFilterLoad should always succeed");
            }
            Operation::SendFilterAdd => {
                let mut random_bytes = Vec::new();
                let size = rng.gen_range(1..=FILTERADD_MAX);
                random_bytes.resize(size, 0);
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

                builder
                    .append(Instruction {
                        inputs: vec![connection_var.index, data_var.index],
                        operation: Operation::SendFilterAdd,
                    })
                    .expect("Inserting SendFilterAdd should always succeed");
            }
            Operation::SendFilterClear => {
                builder.force_append(vec![connection_var.index], op);
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BloomFilterGenerator"
    }
}
