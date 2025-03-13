use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::fri::FriProver;
use frieda::M31;

fn create_evaluations(degree: usize) -> Vec<M31> {
    // Create polynomial evaluations of specified degree
    (0..degree).map(|i| M31::from(i as u32)).collect()
}

fn bench_fri_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("fri_commit");

    // Default parameters for the FRI protocol
    const EXPANSION_FACTOR: usize = 4;
    const BATCH_SIZE: usize = 8;
    const FIELD_SIZE: usize = 31;
    const NUM_QUERIES: usize = 40;
    const FAN_IN: usize = 4;
    const BASE_DIMENSION: usize = 16;

    for &domain_size in &[64, 128, 256, 512] {
        let evals = create_evaluations(domain_size);

        group.bench_with_input(
            BenchmarkId::from_parameter(domain_size),
            &domain_size,
            |b, &size| {
                let prover = FriProver::new(
                    size,
                    EXPANSION_FACTOR,
                    BATCH_SIZE,
                    FIELD_SIZE,
                    NUM_QUERIES,
                    FAN_IN,
                    BASE_DIMENSION,
                );

                let evals_clone = evals.clone();
                b.iter(|| prover.commit(black_box(&evals_clone)))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_fri_commit);
criterion_main!(benches);
