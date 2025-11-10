use crate::Txo;
/// Rust transplation from https://github.com/bitcoin/bitcoin/blob/master/src/common/bloom.cpp
// why do we need this code? because `filterload` message require us that we send the filter itself. So we need to construct the bloom filter on the client (fuzzer) side too.
use murmurs::murmur3_x86_32;
use std::cmp::min;

// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki?plain=1#L51
/// Maximum size for filterload filter
pub(crate) const MAX_BLOOM_FILTER_SIZE: u32 = 36000;
pub(crate) const MAX_HASH_FUNCS: u32 = 50;

// some consts for bloom filter construction
const LN2SQUARED: f64 = 0.4804530139182014246671025263266649717305529515945455;
const LN2: f64 = 0.6931471805599453094172321214581765680755001343602552;

#[derive(Debug, Clone)]
pub struct CBloomFilter {
    data: Vec<u8>,
    n_hash_funcs: u32,
}

// Hash the data
pub fn hash(hashnum: u32, size: usize, key: &[u8]) -> u32 {
    // this needs to be wrapping else it panics in debug mode
    let a = murmur3_x86_32(&key, hashnum.wrapping_mul(0xFBA4C795));
    let b = (size * 8) as u32;
    a % b
}

pub fn filter_insert(data: &mut [u8], n_hash_funcs: u32, key: &[u8]) {
    if data.is_empty() {
        return;
    }
    for i in 0..n_hash_funcs {
        let index = hash(i, data.len(), key);
        let index_into_data = (index >> 3) as usize;
        let bits_to_raise = 7 & index;
        data[index_into_data] |= 1 << bits_to_raise;
    }
}

impl CBloomFilter {
    /// Constructor for this filter
    pub fn new(n_elements: u32, n_fprate: f64) -> Self {
        let size = min(
            (-1 as f64 / LN2SQUARED * n_elements as f64 * n_fprate.ln()) as u32,
            MAX_BLOOM_FILTER_SIZE * 8,
        ) / 8;
        let n_hash_funcs = min(
            (size as f64 * 8f64 / n_elements as f64 * LN2) as u32,
            MAX_HASH_FUNCS,
        );
        let data = vec![0; size as usize];

        Self { data, n_hash_funcs }
    }

    pub fn with_txos(available_txos: Vec<Txo>) -> Self {
        let txos_count = available_txos.len();
        let mut filter = CBloomFilter::new(txos_count as u32, 0.05);

        for txo in available_txos {
            let outpoint = txo.outpoint.0;
            filter.insert(&outpoint);
        }
        filter
    }

    /// Insert a data. (like outpoint ids)
    pub fn insert(&mut self, key: &[u8]) {
        filter_insert(&mut self.data, self.n_hash_funcs, key);
    }

    /// Getter to the `data`
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Getter to the `n_hash_funcs`
    pub fn n_hash_funcs(&self) -> u32 {
        self.n_hash_funcs
    }
}
