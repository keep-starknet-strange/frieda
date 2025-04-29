use lambdaworks_math::circle::cosets::Coset;
use lambdaworks_math::circle::polynomial::{evaluate_cfft, interpolate_cfft};
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::mersenne31::extensions::Degree2ExtensionField;
use lambdaworks_math::field::fields::mersenne31::field::Mersenne31Field;
use lambdaworks_math::polynomial::{pad_with_zero_coefficients_to_length, Polynomial};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use stwo_prover::core::backend::CpuBackend;
use stwo_prover::core::channel::{Blake2sChannel, Channel};
use stwo_prover::core::circle::CirclePoint as StwoCirclePoint;
use stwo_prover::core::fields::{m31::M31, qm31::QM31};
use stwo_prover::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo_prover::core::poly::circle::{CirclePoly, SecureCirclePoly};
use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;

use crate::proof::Proof;

pub fn fast_circle_interpolation(
    xs: &[StwoCirclePoint<M31>],
    evals: &[QM31],
) -> SecureCirclePoly<CpuBackend> {
    let zks = &xs
        .iter()
        .map(|zk| {
            FieldElement::<Degree2ExtensionField>::new([
                FieldElement::<Mersenne31Field>::new(zk.x.0),
                FieldElement::<Mersenne31Field>::new(zk.y.0),
            ])
        })
        .collect::<Vec<_>>();
    let ((first_col, second_col), (third_col, fourth_col)) = rayon::join(
        || {
            interpolate_cm31(
                zks,
                &evals
                    .iter()
                    .map(|vk| {
                        FieldElement::<Degree2ExtensionField>::new([
                            FieldElement::<Mersenne31Field>::new(vk.0 .0 .0),
                            FieldElement::<Mersenne31Field>::new(vk.0 .1 .0),
                        ])
                    })
                    .collect::<Vec<_>>(),
            )
        },
        || {
            interpolate_cm31(
                zks,
                &evals
                    .iter()
                    .map(|vk| {
                        FieldElement::<Degree2ExtensionField>::new([
                            FieldElement::<Mersenne31Field>::new(vk.1 .0 .0),
                            FieldElement::<Mersenne31Field>::new(vk.1 .1 .0),
                        ])
                    })
                    .collect::<Vec<_>>(),
            )
        },
    );

    // concatenate the 4 columns
    SecureCirclePoly([
        CirclePoly::<CpuBackend>::new(first_col),
        CirclePoly::<CpuBackend>::new(second_col),
        CirclePoly::<CpuBackend>::new(third_col),
        CirclePoly::<CpuBackend>::new(fourth_col),
    ])
}

pub fn interpolate_cm31(
    zks: &[FieldElement<Degree2ExtensionField>],
    vks: &[FieldElement<Degree2ExtensionField>],
) -> (Vec<M31>, Vec<M31>) {
    debug_assert_eq!(zks.len(), vks.len());
    debug_assert!((zks.len() - 1).is_power_of_two());

    let n = zks.len() - 1;
    let vprimes = vks
        .into_par_iter()
        .zip_eq(zks)
        .map(|(vk, zk)| vk.clone() * zk.pow(n as u128 / 2))
        .collect::<Vec<_>>();

    let mut pol = fast_interpolation(zks, &vprimes);
    pad_with_zero_coefficients_to_length(&mut pol, n + 1);

    let last_coeff = pol.coefficients.pop().unwrap();

    let coset = Coset::new_standard(n.ilog2());

    let points = Coset::get_coset_points(&coset);

    let f_values = Polynomial::evaluate_fft::<Degree2ExtensionField>(&pol, 1, Some(n)).unwrap();
    let f_values = f_values
        .iter()
        .zip(points)
        .map(|(val, z)| {
            let z = FieldElement::<Degree2ExtensionField>::new([z.x, z.y]);
            ((val + &last_coeff * z.pow(n)) / z.pow(n as u128 / 2)).unwrap()
        })
        .collect::<Vec<_>>();

    let re_col = f_values.iter().map(|x| x.value()[0]).collect::<Vec<_>>();

    let im_col = f_values.iter().map(|x| x.value()[1]).collect::<Vec<_>>();

    let re_fft = interpolate_cfft(re_col.clone());
    let re_evaluations = evaluate_cfft(re_fft.clone());
    debug_assert_eq!(re_evaluations, re_col);
    let im_fft = interpolate_cfft(im_col);

    (
        re_fft
            .into_iter()
            .map(|x| M31::from_u32_unchecked(*x.value()))
            .collect(),
        im_fft
            .into_iter()
            .map(|x| M31::from_u32_unchecked(*x.value()))
            .collect(),
    )
}
pub fn fast_interpolation(
    u: &[FieldElement<Degree2ExtensionField>],
    v: &[FieldElement<Degree2ExtensionField>],
) -> Polynomial<FieldElement<Degree2ExtensionField>> {
    let z0 = &u[0];
    let v0 = &v[0];
    let u = &u[1..];
    let v = &v[1..];
    debug_assert_eq!(u.len(), v.len());
    debug_assert!(u.len().is_power_of_two());

    let tree = build_subproduct_tree(u);

    let k = u.len().ilog2() as usize;
    let m = &tree[k][0];

    let m_deriv = m.differentiate();
    let m_deriv_vals = eval_tree(&m_deriv, &tree, u, 0);

    let c: Vec<FieldElement<Degree2ExtensionField>> = v
        .par_iter()
        .zip(m_deriv_vals.par_iter())
        .map(|(vi, m_prime_ui)| vi * &m_prime_ui.inv().unwrap())
        .collect();

    let poly = linear_combination(u, &c, &tree, k, 0);

    let lambda = (v0 - poly.evaluate(z0)) * m.evaluate(z0).inv().unwrap();

    assert_eq!(&lambda * m.evaluate(z0) + poly.evaluate(z0), *v0);

    poly + m * lambda
}
pub fn build_subproduct_tree(
    u: &[FieldElement<Degree2ExtensionField>],
) -> Vec<Vec<Polynomial<FieldElement<Degree2ExtensionField>>>> {
    // Level 0: polynomials of the form (x - u[i])
    let k = u.len().ilog2() as usize;
    let mut tree: Vec<Vec<Polynomial<FieldElement<Degree2ExtensionField>>>> = Vec::with_capacity(k);
    tree.push(
        u.iter()
            .map(|ui| Polynomial::new(&[-ui, FieldElement::<Degree2ExtensionField>::one()]))
            .collect(),
    );

    for i in 1..=k {
        let polys = (0..(1 << (k - i)))
            .into_par_iter()
            .map(|j| {
                let domain_size = tree[i - 1][2 * j].degree() + tree[i - 1][2 * j + 1].degree() + 1;
                let (p, q) = rayon::join(
                    || {
                        Polynomial::evaluate_fft::<Degree2ExtensionField>(
                            &tree[i - 1][2 * j],
                            1,
                            Some(domain_size),
                        )
                        .unwrap()
                    },
                    || {
                        Polynomial::evaluate_fft::<Degree2ExtensionField>(
                            &tree[i - 1][2 * j + 1],
                            1,
                            Some(domain_size),
                        )
                        .unwrap()
                    },
                );
                let r = p
                    .into_par_iter()
                    .zip_eq(q.into_par_iter())
                    .map(|(a, b)| a * b)
                    .collect::<Vec<_>>();

                Polynomial::interpolate_fft::<Degree2ExtensionField>(&r).unwrap()
            })
            .collect::<Vec<_>>();
        tree.push(polys);
    }
    tree
}

pub fn eval_tree(
    f: &Polynomial<FieldElement<Degree2ExtensionField>>,
    tree: &Vec<Vec<Polynomial<FieldElement<Degree2ExtensionField>>>>,
    points: &[FieldElement<Degree2ExtensionField>],
    index: usize,
) -> Vec<FieldElement<Degree2ExtensionField>> {
    if points.len() == 1 {
        return vec![f
            .coefficients
            .last()
            .unwrap_or(&FieldElement::<Degree2ExtensionField>::zero())
            .clone()];
    }
    let k = points.len().ilog2() as usize;

    let left_poly = &tree[k - 1][2 * index];

    let right_poly = &tree[k - 1][2 * index + 1];

    // Compute remainders of f modulo the children.
    let (_q_left, r_left) = f.fast_division::<Degree2ExtensionField>(left_poly).unwrap();

    let (_q_right, r_right) = f
        .fast_division::<Degree2ExtensionField>(right_poly)
        .unwrap();
    // Split the points into two halves.
    let mid = points.len() / 2;
    let left_points = &points[..mid];
    let right_points = &points[mid..];
    let left_vals = eval_tree(&r_left, tree, left_points, 2 * index);
    let right_vals = eval_tree(&r_right, tree, right_points, 2 * index + 1);
    let mut result = left_vals;
    result.extend(right_vals);
    result
}

pub fn linear_combination(
    u: &[FieldElement<Degree2ExtensionField>],
    c: &[FieldElement<Degree2ExtensionField>],
    subproduct: &Vec<Vec<Polynomial<FieldElement<Degree2ExtensionField>>>>,
    level: usize,
    index: usize,
) -> Polynomial<FieldElement<Degree2ExtensionField>> {
    if c.len() == 1 {
        // Base case: return the constant polynomial equal to c[0].
        return Polynomial::new(c);
    }
    let child_level = level - 1;
    let mid = u.len() / 2;

    let r0 = linear_combination(&u[..mid], &c[..mid], subproduct, child_level, 2 * index);
    let r1 = linear_combination(&u[mid..], &c[mid..], subproduct, child_level, 2 * index + 1);

    let left_poly = &subproduct[child_level][2 * index]; // corresponds to left half
    let right_poly = &subproduct[child_level][2 * index + 1]; // corresponds to right half
    let term1 = right_poly
        .fast_fft_multiplication::<Degree2ExtensionField>(&r0)
        .unwrap();
    let term2 = left_poly
        .fast_fft_multiplication::<Degree2ExtensionField>(&r1)
        .unwrap();
    &term1 + &term2
}

pub fn get_queries_from_proof(proof: Proof, seed: Option<u64>) -> (u32, Vec<usize>) {
    let channel = &mut Blake2sChannel::default();
    if let Some(seed) = seed {
        channel.mix_u64(seed);
    }
    let Ok(mut fri_verifier) = FriVerifier::<Blake2sMerkleChannel>::commit(
        channel,
        proof.pcs_config.fri_config,
        proof.proof,
        vec![CirclePolyDegreeBound::new(proof.log_size_bound)],
    ) else {
        panic!("Failed to commit");
    };
    channel.mix_u64(proof.proof_of_work);
    if channel.trailing_zeros() < proof.pcs_config.pow_bits {
        panic!("Proof of work is invalid");
    }
    let queries = fri_verifier.sample_query_positions(channel);
    queries.into_iter().next().unwrap()
}
#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use super::*;
    use crate::{proof::generate_proof, utils};
    use stwo_prover::core::{
        circle::Coset as StwoCoset, fri::FriConfig, pcs::PcsConfig, poly::circle::CircleDomain,
        utils::bit_reverse_index,
    };
    const PCS_CONFIG: PcsConfig = PcsConfig {
        fri_config: FriConfig {
            log_blowup_factor: 4,
            log_last_layer_degree_bound: 1,
            n_queries: 100,
        },
        pow_bits: 0,
    };
    #[test]
    fn test_something() {
        let data = include_bytes!("../blob").to_vec();
        let poly = utils::polynomial_from_bytes(&data);

        // we should have polys.len().next_power_of_two() samples
        let samples_nb = (1 << (poly.log_size() + 1)) / PCS_CONFIG.fri_config.n_queries;
        let proofs_pos = (0..=samples_nb)
            .into_par_iter()
            .map(|i| {
                let proof = generate_proof(&data, Some(i as u64), PCS_CONFIG);
                let queries = get_queries_from_proof(proof.clone(), Some(i as u64));
                (proof, queries)
            })
            .collect::<Vec<_>>();

        let domain = CircleDomain::new(StwoCoset::half_odds(proofs_pos[0].0.coset_log_size));
        let mut pos_set = HashSet::new();
        let mut pos_vec = Vec::new();
        let mut evals_vec = Vec::new();
        for (proof, (_, pos)) in proofs_pos {
            for (i, p) in pos.iter().enumerate() {
                let point = domain.at(bit_reverse_index(*p, domain.log_size()));
                if pos_set.insert(point) {
                    pos_vec.push(point);
                    evals_vec.push(proof.evaluations[i]);
                }
            }
        }
        println!("pos_set.len(): {:?}", pos_set.len());

        let pos = pos_vec;
        let evals = evals_vec;
        let evals_nb = (1 << poly.log_size()) + 1;

        let interpolated = fast_circle_interpolation(&pos[..evals_nb], &evals[..evals_nb]);

        let interpolated = interpolated.0[0]
            .coeffs
            .iter()
            .zip(interpolated.0[1].coeffs.iter())
            .zip(interpolated.0[2].coeffs.iter())
            .zip(interpolated.0[3].coeffs.iter())
            .flat_map(|(((a, b), c), d)| [a, b, c, d])
            .collect::<Vec<_>>();
        let interpolated_bytes = utils::felts_to_bytes_le(&interpolated);

        data.iter()
            .zip(interpolated_bytes.iter())
            .enumerate()
            .for_each(|(i, (a, b))| {
                if a != b {
                    println!("failed at {i}");
                }
            });
        println!("interpolated_bytes.len(): {:?}", interpolated_bytes.len());
        println!("data.len(): {:?}", data.len());
        assert_eq!(data, interpolated_bytes[..data.len()]);
    }
}
