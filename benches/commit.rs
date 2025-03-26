use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::api::commit;

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    let mut datas = [1024, 4096, 16384, 65536]
        .iter()
        .map(|size| (0..*size).map(|i| (i % 256) as u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    datas.push(include_bytes!("../blob").to_vec());
    for data in datas {
        group.bench_with_input(BenchmarkId::from_parameter(data.len()), &data, |b, data| {
            b.iter(|| commit(black_box(data)))
        });
    }
    group.finish();
}
criterion_group!(benches, bench_commit);
criterion_main!(benches);
