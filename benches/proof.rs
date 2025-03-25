use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::proof::{commit_and_generate_proof, generate_proof, verify_proof};

fn bench_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof");
    for size in [1024, 4096, 16384, 65536].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| generate_proof(black_box(data)))
        });
    }
    group.finish();
}

fn bench_commit_and_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_and_generate_proof");
    for size in [1024, 4096, 16384, 65536].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| commit_and_generate_proof(black_box(data)))
        });
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_proof");
    for size in [1024, 4096, 16384, 65536].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        let (_, proof) = commit_and_generate_proof(black_box(&data));
        group.bench_with_input(BenchmarkId::from_parameter(size), &proof, |b, _| {
            b.iter(|| verify_proof(proof.clone()))
        });
    }
    group.finish();
}
criterion_group!(
    benches,
    bench_generate_proof,
    bench_commit_and_generate_proof,
    bench_verify_proof
);
criterion_main!(benches);
