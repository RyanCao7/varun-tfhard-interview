//! An implementation of a `TranscriptSponge` that uses the Poseidon hash
//! function; Useful for recursive proving.

use super::TranscriptSponge;
use crate::Field;
use itertools::Itertools;
use poseidon::Poseidon;

/// A Poseidon implementation of a transcript sponge.
#[derive(Clone, Debug)]
pub struct PoseidonSponge<F: Field> {
    /// The specific poseidon sponge configuration.
    sponge: Poseidon<F, 3, 2>,
}

impl<F: Field> Default for PoseidonSponge<F> {
    fn default() -> Self {
        Self {
            sponge: Poseidon::new(8, 57),
        }
    }
}

impl<F: Field> TranscriptSponge<F> for PoseidonSponge<F> {
    fn absorb(&mut self, elem: F) {
        self.sponge.update(&[elem]);
    }

    fn absorb_elements(&mut self, elements: &[F]) {
        self.sponge.update(elements);
    }

    fn squeeze(&mut self) -> F {
        self.sponge.squeeze()
    }

    fn squeeze_elements(&mut self, num_elements: usize) -> Vec<F> {
        (0..num_elements)
            .map(|_| self.sponge.squeeze())
            .collect_vec()
    }

    fn absorb_initialization_label(&mut self, label: &str) {
        let label_as_bytes = label.as_bytes();
        let label_as_field_elems = F::vec_from_bytes_le(label_as_bytes);
        self.absorb_elements(&label_as_field_elems);
    }
}
