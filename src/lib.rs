use sha3::{Digest, Sha3_256};
use std::{io::Read, iter};

pub trait Hasher {
    fn hash(item: impl AsRef<[u8]>) -> u64;
}

pub type HashFn<T> = Box<dyn Fn(&T) -> u64>;

pub struct DefaultHasher {}

impl Hasher for DefaultHasher {
    fn hash(item: impl AsRef<[u8]>) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(item);
        let result = hasher.finalize();
        let mut buf = [0; 8];
        let mut handle = result.take(8);
        handle.read_exact(&mut buf).unwrap();
        u64::from_be_bytes(buf)
    }
}

pub struct Builder {
    num_items: u32,
    fp_rate: f32,
    num_hash_fns: Option<u32>,
}

impl Builder {
    fn new(num_items: u32, fp_rate: f32) -> Builder {
        Self {
            num_items,
            num_hash_fns: None,
            fp_rate,
        }
    }
    #[allow(dead_code)]
    fn num_hash_funcs(mut self, num_hash_fns: u32) -> Builder {
        self.num_hash_fns = Some(num_hash_fns);
        self
    }
    fn build<H: Hasher, T: AsRef<[u8]>>(self) -> BloomFilter<T> {
        let num_hash_fns = match self.num_hash_fns {
            Some(n) => n,
            None => optimal_num_hash_fns(self.num_items, self.fp_rate),
        };
        let mut hash_fns: Vec<HashFn<T>> = vec![];
        for i in 0..=num_hash_fns {
            let f = Box::new(move |elem: &T| {
                element_hasher::<H, T>(elem, i as u64, self.num_items as u64)
            });
            hash_fns.push(f);
        }
        let required_bits = optimal_bits_needed(self.num_items, self.fp_rate);

        // We'll use u64's to store data in our bloom filter.
        let size = (required_bits as f64 / 8.0).ceil() as usize;
        BloomFilter {
            bits: iter::repeat(0).take(size).collect(),
            hash_fns,
        }
    }
}

pub struct BloomFilter<T: AsRef<[u8]>> {
    pub bits: Vec<u8>,
    hash_fns: Vec<HashFn<T>>,
}

impl<T: AsRef<[u8]>> BloomFilter<T> {
    pub fn insert(&mut self, elem: T) {
        self.hash_fns.iter().for_each(|f| {
            let idx = f(&elem);
            let pos = idx / 8;
            let pos_within_bits = idx % 8;
            match self.bits.get_mut(pos as usize) {
                Some(b) => {
                    *b |= 1 << pos_within_bits;
                }
                None => panic!("index did not exist"),
            }
        });
    }
    pub fn has(&self, elem: T) -> bool {
        for f in self.hash_fns.iter() {
            let idx = f(&elem);
            let pos = idx / 8;
            let pos_within_bits = idx % 8;
            match self.bits.get(pos as usize) {
                Some(b) => {
                    // Get the individual bit at the position determined by the hasher function.
                    let bit = (*b >> pos_within_bits) & 1;
                    // If the bit is 0, the element is definitely not in the bloom filter.
                    if bit == 0 {
                        return false;
                    }
                }
                // The position will always refer to a valid index of our bits vector.
                None => unreachable!(),
            }
        }
        true
    }
}

/// Computes the optimal bits needed to store n items with an expected false positive
/// rate in the range [0, 1.0]
/// Rounds up to the nearest integer.
pub fn optimal_bits_needed(num_items: u32, fp_rate: f32) -> u32 {
    let bits = (-(num_items as f32) * fp_rate.ln()) / 2f32.ln().powi(2);
    bits.ceil() as u32
}

/// Computes the optimal number of hash functions needed a bloom filter
/// with an expected n num_items, and a desired false positive rate.
/// Rounds up to the nearest integer.
pub fn optimal_num_hash_fns(num_items: u32, fp_rate: f32) -> u32 {
    assert!(num_items > 0);
    let bits = optimal_bits_needed(num_items, fp_rate);
    let num_hash_fns = (bits as f32 / num_items as f32) * 2f32.ln();
    num_hash_fns.ceil() as u32
}

fn element_hasher<H: Hasher, T: AsRef<[u8]>>(item: &T, i: u64, m: u64) -> u64 {
    assert!(i < 32);
    let num = H::hash(item);
    let num = num.checked_add(i).unwrap();
    num % m
}

/// Converts an iterator into a bloom filter with a default hasher
/// and sensible false positive rate of 0.03.
/// TODO: Figure out how to customize these values
/// within this trait implementation.
impl<T: AsRef<[u8]>> FromIterator<T> for BloomFilter<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let items: Vec<T> = iter.into_iter().collect();
        let num_items = items.len() + 100;
        let mut bloom_filter = Builder::new(num_items as u32, 0.03).build::<DefaultHasher, T>();
        for i in items.into_iter() {
            bloom_filter.insert(i);
        }
        bloom_filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok() {
        let num_items: u32 = 50;
        let fp_rate: f32 = 0.03;
        let mut bf = Builder::new(num_items, fp_rate).build::<DefaultHasher, &str>();
        let wanted_bit_count = optimal_bits_needed(num_items, fp_rate);
        let wanted_byte_count = (wanted_bit_count as f64 / 8.0).ceil() as u32;
        assert_eq!(wanted_byte_count, bf.bits.len() as u32);
        bf.insert("hello");
        assert_eq!(false, bf.has("world"));
    }

    #[test]
    fn from_iterator() {
        let items = vec!["wow", "rust", "is", "so", "cool"];
        let bf: BloomFilter<&str> = items.into_iter().collect();
        assert_eq!(false, bf.has("go"));
    }

    #[test]
    fn optimal_values() {
        assert_eq!(335, optimal_bits_needed(100, 0.20));
        assert_eq!(730, optimal_bits_needed(100, 0.03));
        assert_eq!(959, optimal_bits_needed(100, 0.01));
        assert_eq!(10, optimal_bits_needed(1, 0.01));
        assert_eq!(96, optimal_bits_needed(10, 0.01));

        assert_eq!(3, optimal_num_hash_fns(100, 0.20));
        assert_eq!(6, optimal_num_hash_fns(100, 0.03));
        assert_eq!(7, optimal_num_hash_fns(100, 0.01));
        assert_eq!(7, optimal_num_hash_fns(1, 0.01));
        assert_eq!(7, optimal_num_hash_fns(10, 0.01));
    }

    /// Empirically trying out varying values of M and K to determine
    /// false positive rates and see how these evolve based on
    /// the number of insertions into the filter.
    #[test]
    fn tweaking_parameters() {
        for n in 3..=20 {
            let elems = (0..n).map(|i| i.to_string()).collect::<Vec<String>>();
            for k in 1..=n - 1 {
                let mut false_positives = 0;
                let mut bf = Builder::new(n, 0.03)
                    .num_hash_funcs(k as u32)
                    .build::<DefaultHasher, &str>();
                for (idx, elem) in elems.iter().enumerate() {
                    bf.insert(&elem);
                    if bf.has("foo") {
                        false_positives += 1;
                    }
                    let fp_rate = false_positives as f64 / elems.len() as f64;
                    println!(
                        "capacity={}, num_hash_fns={}, elems_inserted={}, false_positive_rate={}",
                        n,
                        k,
                        idx + 1,
                        fp_rate,
                    );
                }
            }
        }
    }

    // TODO: Use the plotters library to understand how it goes up
    // and the relationship between the different parameters.
    // Criterion benchmark blackbox against a prod crate.
    // Flame graph to understand bottlenecks.
    // Unsafe?
    #[test]
    fn large_capacity() {
        let elems = (0..1000).map(|i| i.to_string()).collect::<Vec<String>>();
        for k in 1..=20 {
            let mut false_positives = 0;
            let mut bf = Builder::new(1000, 0.03)
                .num_hash_funcs(k as u32)
                .build::<DefaultHasher, &str>();
            for (idx, elem) in elems.iter().enumerate() {
                bf.insert(&elem);
                if bf.has("foo") {
                    false_positives += 1;
                }
                let fp_rate = false_positives as f64 / elems.len() as f64;
                println!(
                    "capacity=1000, num_hash_fns={}, elems_inserted={}, false_positive_rate={}",
                    k,
                    idx + 1,
                    fp_rate,
                );
            }
        }
    }
}
