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
                209, 162, 213, 6, 157, 197, 135, 229, 93, 194, 156, 198, 37, 90, 249, 55, 255, 127,
                237, 14, 228, 27, 223, 90, 249, 135, 23, 249, 215, 79, 96, 232
            ]
        );
    }
}
