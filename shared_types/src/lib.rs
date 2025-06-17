pub mod transcript;

use halo2curves::ff::FromUniformBytes;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

pub use halo2curves::ff::Field as ff_field;

pub use halo2curves;
pub use halo2curves::bn256::{Fq, Fr};
pub use poseidon::Poseidon;
use std::hash::Hash;

use halo2curves::CurveExt;
pub use halo2curves::{bn256::G1 as Bn256Point, group::Group};
pub type Scalar = <Bn256Point as Group>::Scalar;
pub type Base = <Bn256Point as CurveExt>::Base;

/// The primary finite field used within a GKR circuit, as well as within
/// sumcheck. Note that the field's size should be large enough such that
/// d / |F| bits of computational soundness is considered secure!
pub trait Field:
ff_field
    + FromUniformBytes<64> // only need this bc of Poseidon transcript,
                              // see func `next_field_element_without_rejection`
    + Hash
    + Ord
    + Serialize
    + for<'de> Deserialize<'de>
    + HasByteRepresentation
{
}

impl<
        F: ff_field
            + FromUniformBytes<64>
            + Hash
            + Ord
            + Serialize
            + for<'de> Deserialize<'de>
            + HasByteRepresentation,
    > Field for F
{
}

/// Simple trait which allows us to convert to and from
/// a little-endian byte representation.
pub trait HasByteRepresentation {
    /// Number of bytes within the element's representation.
    const REPR_NUM_BYTES: usize;
    /// Constructor which creates an instance of the element from a vec of
    /// less than or equal to length `REPR_NUM_BYTES`.
    /// If length less than `REPR_NUM_BYTES`, pads the most significant
    /// bits with 0s until it is of equal length to `REPR_NUM_BYTES`.
    fn from_bytes_le(bytes: &[u8]) -> Self;
    /// Function which creates an equivalent representation of the element
    /// in a byte array of length `REPR_NUM_BYTES`.
    fn to_bytes_le(&self) -> Vec<u8>;

    /// Similar to `to_bytes_le` but returns chunks of `u64`s.
    fn to_u64s_le(&self) -> Vec<u64>;

    /// Similar to `from_bytes_le` but takes chunks of `u64`s.
    fn from_u64s_le(words: Vec<u64>) -> Self
    where
        Self: Sized;

    /// Creates a Vec of elements from an arbitrary string
    /// of bytes.
    fn vec_from_bytes_le(bytes: &[u8]) -> Vec<Self>
    where
        Self: Sized;
}

impl HasByteRepresentation for Fr {
    const REPR_NUM_BYTES: usize = 32;

    fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.len() > Self::REPR_NUM_BYTES {
            panic!("Error: Attempted to convert from greater than 32-length byte vector into Fr")
        }
        // Pad with 0s at the most significant bits if less than 32 bytes.
        let bytes_len_32_slice: [u8; 32] = if bytes.len() < Self::REPR_NUM_BYTES {
            let padding = vec![0_u8; Self::REPR_NUM_BYTES - bytes.len()];
            let bytes_owned = bytes.to_owned();
            bytes_owned
                .into_iter()
                .chain(padding)
                .collect_vec()
                .try_into()
                .unwrap()
        } else {
            bytes.try_into().unwrap()
        };
        Fr::from_bytes(&bytes_len_32_slice).unwrap()
    }

    fn to_bytes_le(&self) -> Vec<u8> {
        Fr::to_bytes(self).to_vec()
    }

    fn to_u64s_le(&self) -> Vec<u64> {
        let bytes = self.to_bytes_le();

        let fold_bytes = |acc, x: &u8| (acc << 8) + (*x as u64);

        vec![
            bytes[0..8].iter().rev().fold(0, fold_bytes),
            bytes[8..16].iter().rev().fold(0, fold_bytes),
            bytes[16..24].iter().rev().fold(0, fold_bytes),
            bytes[24..32].iter().rev().fold(0, fold_bytes),
        ]
    }

    fn from_u64s_le(words: Vec<u64>) -> Self
    where
        Self: Sized,
    {
        let mask_8bit = (1_u64 << 8) - 1;

        Self::from_bytes_le(&[
            (words[0] & mask_8bit) as u8,
            ((words[0] & (mask_8bit << 8)) >> 8) as u8,
            ((words[0] & (mask_8bit << 16)) >> 16) as u8,
            ((words[0] & (mask_8bit << 24)) >> 24) as u8,
            ((words[0] & (mask_8bit << 32)) >> 32) as u8,
            ((words[0] & (mask_8bit << 40)) >> 40) as u8,
            ((words[0] & (mask_8bit << 48)) >> 48) as u8,
            ((words[0] & (mask_8bit << 56)) >> 56) as u8,
            (words[1] & mask_8bit) as u8,
            ((words[1] & (mask_8bit << 8)) >> 8) as u8,
            ((words[1] & (mask_8bit << 16)) >> 16) as u8,
            ((words[1] & (mask_8bit << 24)) >> 24) as u8,
            ((words[1] & (mask_8bit << 32)) >> 32) as u8,
            ((words[1] & (mask_8bit << 40)) >> 40) as u8,
            ((words[1] & (mask_8bit << 48)) >> 48) as u8,
            ((words[1] & (mask_8bit << 56)) >> 56) as u8,
            (words[2] & mask_8bit) as u8,
            ((words[2] & (mask_8bit << 8)) >> 8) as u8,
            ((words[2] & (mask_8bit << 16)) >> 16) as u8,
            ((words[2] & (mask_8bit << 24)) >> 24) as u8,
            ((words[2] & (mask_8bit << 32)) >> 32) as u8,
            ((words[2] & (mask_8bit << 40)) >> 40) as u8,
            ((words[2] & (mask_8bit << 48)) >> 48) as u8,
            ((words[2] & (mask_8bit << 56)) >> 56) as u8,
            (words[3] & mask_8bit) as u8,
            ((words[3] & (mask_8bit << 8)) >> 8) as u8,
            ((words[3] & (mask_8bit << 16)) >> 16) as u8,
            ((words[3] & (mask_8bit << 24)) >> 24) as u8,
            ((words[3] & (mask_8bit << 32)) >> 32) as u8,
            ((words[3] & (mask_8bit << 40)) >> 40) as u8,
            ((words[3] & (mask_8bit << 48)) >> 48) as u8,
            ((words[3] & (mask_8bit << 56)) >> 56) as u8,
        ])
    }

    fn vec_from_bytes_le(bytes: &[u8]) -> Vec<Self>
    where
        Self: Sized,
    {
        bytes
            .chunks(Self::REPR_NUM_BYTES)
            .map(Self::from_bytes_le)
            .collect()
    }
}
