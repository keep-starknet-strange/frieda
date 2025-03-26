use stwo_prover::core::{
    backend::CpuBackend,
    channel::Blake2sChannel,
    circle::Coset,
    fields::m31::BaseField,
    pcs::CommitmentTreeProver,
    poly::circle::{CirclePoly, PolyOps},
    vcs::blake2_merkle::Blake2sMerkleChannel,
};

use crate::utils;
pub type Commitment = [u8; 32];

pub fn commit(data: &[u8], log_blowup_factor: u32) -> Commitment {
    let mut coefficients = utils::bytes_to_felt_le(data);
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    coefficients.resize(next_power_of_2, BaseField::from(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients);
    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    CommitmentTreeProver::<CpuBackend, Blake2sMerkleChannel>::new(
        vec![polynomial],
        log_blowup_factor,
        &mut Blake2sChannel::default(),
        &twiddles,
    )
    .commitment
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
                26, 61, 225, 48, 151, 109, 146, 25, 225, 155, 12, 46, 255, 207, 162, 111, 142, 227,
                103, 53, 16, 118, 190, 82, 170, 154, 211, 98, 81, 236, 197, 122
            ]
        );
    }
}
