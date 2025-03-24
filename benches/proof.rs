use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::proof::{commit_and_generate_proof, generate_proof};

fn bench_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof");
    for size in [1024, 4096, 16384, 65536].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| generate_proof(black_box(&data)))
        });
    }
    group.finish();
}

fn bench_commit_and_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_and_generate_proof");
    for size in [1024, 4096, 16384, 65536].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| commit_and_generate_proof(black_box(&data)))
        });
    }
    group.finish();
}
criterion_group!(
    benches,
    bench_generate_proof,
    bench_commit_and_generate_proof
);
criterion_main!(benches);
