use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use frieda::api::{commit, sample};

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    for size in [1024, 4096, 16384, 65536].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| commit(black_box(&data)))
        });
    }
    group.finish();
}

fn bench_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample");
    for size in [1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            let commitment = commit(&data).unwrap();
            b.iter(|| sample(black_box(&commitment)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_commit, bench_sample);
criterion_main!(benches);