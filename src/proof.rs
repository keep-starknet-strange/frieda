use stwo_prover::core::{
    backend::CpuBackend,
    channel::Blake2sChannel,
    circle::Coset,
    fields::{m31::BaseField, qm31::SecureField},
    fri::{FriConfig, FriProof, FriProver},
    poly::{
        circle::{CircleDomain, CircleEvaluation, CirclePoly, PolyOps, SecureEvaluation},
        BitReversedOrder,
    },
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
};

use crate::{commit::Commitment, utils};

pub fn generate_proof<'a>(data: &[u8]) -> FriProof<Blake2sMerkleHasher> {
    let mut coefficients = utils::bytes_to_felt_le(data);
    let log_blowup_factor = 4;
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    coefficients.resize(next_power_of_2, BaseField::from(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients);
    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor - 1);
    let domain = CircleDomain::new(coset);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations: CircleEvaluation<CpuBackend, BaseField, BitReversedOrder> =
        polynomial.evaluate(domain);
    let secure_evaluations: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
            domain,
            evaluations.into_iter().map(SecureField::from).collect(),
        );

    // 0 is the degree of the polynomial of the last layer (the polynomial is constant)
    // the polynomial is expanded by 2 ** log_blowup_factor
    // 20 is the number of queries
    let config = FriConfig::new(0, log_blowup_factor, 20);

    let proof = FriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
        &mut Blake2sChannel::default(),
        config,
        &[secure_evaluations],
        &twiddles,
    )
    .decommit(&mut Blake2sChannel::default());
    proof.0
}

pub fn commit_and_generate_proof(data: &[u8]) -> (Commitment, FriProof<Blake2sMerkleHasher>) {
    let mut coefficients = utils::bytes_to_felt_le(data);
    let log_blowup_factor = 4;
    let next_power_of_2 = 1 << (coefficients.len() as f64).log2().ceil() as u32;
    coefficients.resize(next_power_of_2, BaseField::from(0));
    let polynomial = CirclePoly::<CpuBackend>::new(coefficients);
    let coset = Coset::half_odds(polynomial.log_size() + log_blowup_factor - 1);
    let domain = CircleDomain::new(coset);
    let twiddles = CpuBackend::precompute_twiddles(coset);
    let evaluations: CircleEvaluation<CpuBackend, BaseField, BitReversedOrder> =
        polynomial.evaluate(domain);
    let secure_evaluations: SecureEvaluation<CpuBackend, BitReversedOrder> =
        SecureEvaluation::<CpuBackend, BitReversedOrder>::new(
            domain,
            evaluations.into_iter().map(SecureField::from).collect(),
        );

    // 0 is the degree of the polynomial of the last layer (the polynomial is constant)
    // the polynomial is expanded by 2 ** log_blowup_factor
    // 20 is the number of queries
    let config = FriConfig::new(0, log_blowup_factor, 20);

    let proof = FriProver::<CpuBackend, Blake2sMerkleChannel>::commit(
        &mut Blake2sChannel::default(),
        config,
        &[secure_evaluations],
        &twiddles,
    )
    .decommit(&mut Blake2sChannel::default());
    (proof.first_layer.commitment.0, proof.0)
}

#[cfg(test)]
mod tests {
    use crate::commit::commit;

    use super::*;

    #[test]
    fn test_generate_proof() {
        let data = include_bytes!("../blob");
        let commitment = commit(data);
        let proof = generate_proof(data);
        assert_eq!(proof.first_layer.commitment.0, commitment);
    }

    #[test]
    fn test_commit_and_generate_proof() {
        let data = include_bytes!("../blob");
        let (commitment, proof) = commit_and_generate_proof(data);
        assert_eq!(commitment, commit(data));
        assert_eq!(proof.first_layer.commitment.0, commitment);
    }
}
