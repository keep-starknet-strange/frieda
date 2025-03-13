use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use frieda::polynomial::{evaluate_polynomial, fft, ifft};
use frieda::M31;

fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_operations");

    // Generate field elements for benchmarking
    let a = M31::from(123456);
    let b = M31::from(789012);

    group.bench_function("add", |bencher| bencher.iter(|| a + black_box(b)));

    group.bench_function("mul", |bencher| bencher.iter(|| a * black_box(b)));

    group.bench_function("div", |bencher| bencher.iter(|| a / black_box(b)));

    group.bench_function("pow", |bencher| {
        bencher.iter(|| {
            let x = black_box(a);
            x * x * x * x * x // x^5
        })
    });

    group.finish();
}

fn bench_polynomial_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_operations");

    for &size in &[32, 64, 128, 256, 512] {
        // Generate polynomial for benchmarking
        let poly: Vec<M31> = (0..size).map(|i| M31::from(i as u32)).collect();

        group.bench_with_input(BenchmarkId::new("fft", size), &size, |b, &size| {
            let poly_clone = poly.clone();
            b.iter(|| fft(black_box(poly_clone.clone()), black_box(size * 2)))
        });

        let domain_size = size * 2;
        let fft_result = fft(poly.clone(), domain_size).unwrap();

        group.bench_with_input(BenchmarkId::new("ifft", size), &size, |b, &size| {
            let fft_clone = fft_result.clone();
            b.iter(|| ifft(black_box(fft_clone.clone()), black_box(size * 2)))
        });

        group.bench_with_input(BenchmarkId::new("evaluate", size), &size, |b, &_size| {
            let point = M31::from(42);
            let poly_clone = poly.clone();
            b.iter(|| evaluate_polynomial(black_box(&poly_clone), black_box(point)))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_field_operations, bench_polynomial_operations);
criterion_main!(benches);
