use bloomfilter::Bloom;
use bloomy::{BloomBuilder, BloomFilter};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_fibs(c: &mut Criterion) {
    let capacity = 100_000;
    let fp_rate = 0.01;

    let mut bloom = Bloom::new_for_fp_rate(capacity, fp_rate);

    let mut bf: BloomFilter<&str> = BloomBuilder::new(capacity as u32, fp_rate as f32).build();

    let mut group = c.benchmark_group("crate comparisons");
    group.bench_function("bloomy crate", |b| {
        b.iter(|| {
            bloom.set("nyancat");
            bloom.check("nyancat");
        })
    });
    group.bench_function("bloomfilter crate", |b| {
        b.iter(|| {
            bf.insert("nyancat");
            bf.has("nyancat");
        })
    });
    group.finish();
}

criterion_group!(benches, bench_fibs);
criterion_main!(benches);
