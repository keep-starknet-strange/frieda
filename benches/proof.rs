use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::proof::{commit_and_generate_proof, generate_proof, verify_proof};
use stwo_prover::core::pcs::PcsConfig;

const PCS_CONFIG: PcsConfig = PcsConfig {
    fri_config: stwo_prover::core::fri::FriConfig {
        log_blowup_factor: 4,
        log_last_layer_degree_bound: 0,
        n_queries: 20,
    },
    pow_bits: 20,
};

fn bench_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof");
    let mut datas = [1024, 4096, 16384, 65536]
        .iter()
        .map(|size| (0..*size).map(|i| (i % 256) as u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    datas.push(include_bytes!("../blob").to_vec());
    for data in datas {
        group.bench_with_input(BenchmarkId::from_parameter(data.len()), &data, |b, data| {
            b.iter(|| generate_proof(black_box(data), Some(data.len() as u64), PCS_CONFIG))
        });
    }
    group.finish();
}

fn bench_commit_and_generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_and_generate_proof");
    let mut datas = [1024, 4096, 16384, 65536]
        .iter()
        .map(|size| (0..*size).map(|i| (i % 256) as u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    datas.push(include_bytes!("../blob").to_vec());
    for data in datas {
        group.bench_with_input(BenchmarkId::from_parameter(data.len()), &data, |b, data| {
            b.iter(|| {
                commit_and_generate_proof(black_box(data), Some(data.len() as u64), PCS_CONFIG)
            })
        });
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_proof");
    let mut datas = [1024, 4096, 16384, 65536]
        .iter()
        .map(|size| (0..*size).map(|i| (i % 256) as u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    datas.push(include_bytes!("../blob").to_vec());
    for data in datas {
        let (_, proof) =
            commit_and_generate_proof(black_box(&data), Some(data.len() as u64), PCS_CONFIG);
        group.bench_with_input(BenchmarkId::from_parameter(data.len()), &proof, |b, _| {
            b.iter(|| verify_proof(proof.clone(), Some(data.len() as u64)))
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
