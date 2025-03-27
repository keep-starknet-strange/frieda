use bitvec::{field::BitField, order::Lsb0, vec::BitVec};
use stwo_prover::core::{
    backend::CpuBackend,
    fields::m31::BaseField,
    poly::circle::{CirclePoly, SecureCirclePoly},
};

/// Convert a byte slice to a vector of BaseField elements, where each element is the
/// a felt containing the bytes. A felt can be up to 2**31 - 1
pub fn bytes_to_felt_le(data: &[u8]) -> Vec<BaseField> {
    let bitvec = BitVec::<u8, Lsb0>::from_slice(data);
    bitvec
        .chunks(30)
        .map(|chunk| {
            let value = chunk.load::<u32>();
            BaseField::from_u32_unchecked(value)
        })
        .collect()
}

pub fn polynomial_from_bytes(data: &[u8]) -> SecureCirclePoly<CpuBackend> {
    let mut coefficients = bytes_to_felt_le(data);
    let next_power_of_2 = 1 << ((coefficients.len() as f64).log2().ceil() as u32).max(2);
    coefficients.resize(next_power_of_2, BaseField::from(0));
    SecureCirclePoly(
        coefficients
            .chunks(coefficients.len() / 4)
            .map(|chunk| CirclePoly::<CpuBackend>::new(chunk.to_vec()))
            .collect::<Vec<CirclePoly<CpuBackend>>>()
            .try_into()
            .unwrap(),
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_bytes_to_one_felt() {
        let mut data = [0];
        for i in 0..=255 {
            data[0] = i;
            let felt = bytes_to_felt_le(&data);
            assert_eq!(felt.len(), 1);
            assert_eq!(felt[0], BaseField::from(i as u32));
        }
    }

    #[test]
    fn test_bytes_to_two_felt() {
        for i in 0..=512 {
            let i_bits: BitVec<u8> = BitVec::<u8, Lsb0>::from_slice(&u32::to_le_bytes(i));
            let mut data = BitVec::<u8, Lsb0>::with_capacity(60);
            data.extend_from_bitslice(&i_bits[0..30]);
            data.extend_from_bitslice(&i_bits[0..30]);

            let felt = bytes_to_felt_le(data.as_raw_slice());
            assert_eq!(felt.len(), 3);
            assert_eq!(felt[0], BaseField::from(i));
            assert_eq!(felt[1], BaseField::from(i));
            // when converted to bytes it gets padded with 4 0s to reach 64 bits (8 bytes)
            assert_eq!(felt[2], BaseField::from(0));
        }
    }
}
