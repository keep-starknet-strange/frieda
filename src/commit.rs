use stwo_prover::core::{
    backend::CpuBackend,
    circle::Coset,
    poly::circle::{CircleDomain, PolyOps},
    vcs::{blake2_merkle::Blake2sMerkleHasher, prover::MerkleProver},
};

use crate::utils;
pub type Commitment = [u8; 32];

pub fn commit(data: &[u8], log_blowup_factor: u32) -> Commitment {
    let polynomial = utils::polynomial_from_bytes(data);

    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor - 1);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations = polynomial.evaluate_with_twiddles(CircleDomain::new(coset), &twiddles);
    MerkleProver::<CpuBackend, Blake2sMerkleHasher>::commit(
        evaluations.columns.iter().collect::<Vec<_>>(),
    )
    .root()
    .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit() {
        let data = include_bytes!("../blob");
        assert_eq!(
            commit(data, 4),
            [
                125, 189, 194, 110, 217, 237, 26, 95, 241, 18, 250, 155, 47, 30, 202, 166, 13, 101,
                238, 163, 13, 39, 226, 31, 58, 242, 172, 243, 205, 190, 43, 40
            ]
        );
    }
}
