pub mod poseidon_sponge;
use std::fmt::Debug;

/// A `TranscriptSponge` provides the basic interface for a cryptographic sponge
/// operating on field elements. It is typically used for representing the
/// transcript of an interactive protocol turned non-interactive view
/// Fiat-Shamir.
pub trait TranscriptSponge<F>: Clone + Send + Sync + Default + Debug {
    /// Absorb the initialization label.
    fn absorb_initialization_label(&mut self, label: &str);

    /// Absorb a single field element `elem`.
    fn absorb(&mut self, elem: F);

    /// Absorb a list of field elements sequentially.
    fn absorb_elements(&mut self, elements: &[F]);

    /// Generate a field element by squeezing the sponge. Internal state is
    /// modified.
    fn squeeze(&mut self) -> F;

    /// Generate a sequence of field elements by squeezing the sponge
    /// `num_elements` times. Internal state is modified.
    fn squeeze_elements(&mut self, num_elements: usize) -> Vec<F>;
}
