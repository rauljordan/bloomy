use bloomy::{Builder, DefaultHasher};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("insert=1, capacity=100", |b| {
        let num_items = 100;
        let fp_rate = 0.03;
        let mut bf = Builder::new(num_items, fp_rate).build::<DefaultHasher, &str>();
        b.iter(|| bf.insert(black_box("hi")))
    });
    c.bench_function("insert=1, capacity=10,000", |b| {
        let num_items = 10_000;
        let fp_rate = 0.03;
        let mut bf = Builder::new(num_items, fp_rate).build::<DefaultHasher, &str>();
        b.iter(|| bf.insert(black_box("hi")))
    });
    c.bench_function("insert=10_000, capacity=100_000", |b| {
        let mut items = vec![];
        for i in 0..10_000 {
            items.push(format!("{}", i));
        }
        let num_items = 100_000;
        let fp_rate = 0.03;
        let mut bf = Builder::new(num_items, fp_rate).build::<DefaultHasher, &str>();
        b.iter(|| {
            for item in items.iter() {
                bf.insert(black_box(item))
            }
        })
    });
    c.bench_function("has, capacity=100_000", |b| {
        let mut items = vec![];
        for i in 0..10_000 {
            items.push(format!("{}", i));
        }
        let num_items = 100_000;
        let fp_rate = 0.03;
        let bf = Builder::new(num_items, fp_rate).build::<DefaultHasher, &str>();
        b.iter(|| bf.has("5"))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
