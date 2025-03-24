use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::api::commit;

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
criterion_group!(benches, bench_commit);
criterion_main!(benches);
