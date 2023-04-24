# Flowerbloom

Fast bloom filter library written in Rust. My attempt at creating a production-ready
crate with as nice of an API, documentation, tests, and CI as possible. Hilariously overengineered
on purpose to showcase how robust Rust's tooling is for writing and maintaining open source
crates.


## Benchmarks

Flowerbloom is fast compared to the other popular bloomfilter crate given its simplicity
and choice of default hashing operations.

```
# Inserting and checking into a capacity 100k bloom filter with fp rate of 0.03

crate comparisons/flowerbloom crate                                                                            
                        time:   [71.530 ns 71.620 ns 71.737 ns]
crate comparisons/bloomfilter crate                                                                             
                        time:   [17.842 µs 17.887 µs 17.946 µs]
```

## TODO

- [ ] Proptest
- [ ] Plotters empirical vs. analytical false positive results
- [x] Cargo bench with criterion
- [x] Crates docs and doctest
- [x] Check if target fp rate is reached
- [ ] What happens if filter gets fully filled up?
- [ ] Misc methods, clear, is_empty, fill_rate, etc.

## License

Bloomy is licensed under the MIT license.
