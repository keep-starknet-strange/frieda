use stwo_prover::core::{
    backend::CpuBackend,
    circle::Coset,
    fields::{m31::BaseField, qm31::SecureField},
    poly::{
        circle::{CircleDomain, CircleEvaluation, CirclePoly, SecureEvaluation},
        BitReversedOrder,
    },
    vcs::{blake2_merkle::Blake2sMerkleHasher, prover::MerkleProver},
};

use crate::utils;
pub type Commitment = [u8; 32];

pub fn commit(data: &[u8]) -> Commitment {
    let mut coefficients = utils::bytes_to_felt_le(data);
    let log_blowup_factor = 4;
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    coefficients.resize(next_power_of_2, BaseField::from(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients);
    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor - 1);
    let domain = CircleDomain::new(coset);

    let evaluations: CircleEvaluation<CpuBackend, BaseField, BitReversedOrder> =
        polynomial.evaluate(domain);
    let secure_evaluations: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
            domain,
            evaluations.into_iter().map(SecureField::from).collect(),
        );

    let merkle_tree = MerkleProver::<CpuBackend, Blake2sMerkleHasher>::commit(
        secure_evaluations
            .columns
            .iter()
            .collect::<Vec<&Vec<BaseField>>>(),
    );
    merkle_tree.root().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit() {
        let data = include_bytes!("../blob");
        assert_eq!(
            commit(data),
            [
                26, 61, 225, 48, 151, 109, 146, 25, 225, 155, 12, 46, 255, 207, 162, 111, 142, 227,
                103, 53, 16, 118, 190, 82, 170, 154, 211, 98, 81, 236, 197, 122
            ]
        );
    }
}
