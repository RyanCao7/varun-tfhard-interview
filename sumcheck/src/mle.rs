use ark_std::log2;
use shared_types::Field;

/// Represents a multilinear polynomial f(x_1, ..., x_n) by storing its explicit
/// evaluations over the boolean hypercube, i.e. f(b_1, ..., b_n) for
/// b_1, ..., b_n \in \{0, 1}^n.
///
/// Recall that a multilinear polynomial is uniquely defined by its evaluations
/// over the boolean hypercube, and indeed we have that
/// f(x_1, ..., x_n) = \sum_{b_1, ..., b_n} \eq(x_1, ..., x_n; b_1, ..., b_n) * f(b_1, ..., b_n)
/// for any x_1, ..., x_n \in \mathbb{F}^n.
///
/// As a hint, we note that a "partially evaluated" multilinear extension
/// is also a multilinear extension and can also be described in terms of its
/// evaluations over the hypercube for its remaining non-evaluated variables.
/// Concretely, we can represent a partial evaluation
/// f(r_1, ..., r_k, b_{k + 1}, ..., b_n)
/// by simply computing the correct evaluations over b_{k + 1}, ..., b_n and
/// storing those.
///
/// As a second hint, we give as fact the following relationship (please
/// justify on your own!):
/// f(r_1, b_2, ..., b_n) = (1 - r_1) * f(0, b_2, ..., b_n) + r_1 * f(1, b_2, ..., b_n)
#[derive(Clone)]
pub struct MultilinearExtension<F> {
    bookkeping_table: Vec<F>,
    num_vars: usize,
}

impl<F: Field> MultilinearExtension<F> {
    /// Create a new [MultilinearExtension] from a [`Vec<F>`] of evaluations.
    pub fn new(bookkeeping_table_vec: Vec<F>) -> Self {
        let num_vars = log2(bookkeeping_table_vec.len()) as usize;
        Self {
            bookkeping_table: bookkeeping_table_vec,
            num_vars,
        }
    }

    /// Returns `n`, the number of arguments `\tilde{f}` takes.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Returns the `idx`-th element, if `idx` is in the range `[0,
    /// 2^self.num_vars)`.
    pub fn get(&self, idx: usize) -> Option<F> {
        if idx >= (1 << self.num_vars()) {
            // `idx` is out of range.
            None
        } else if idx >= self.bookkeping_table.len() {
            // `idx` is within range, but value is implicitly assumed to be
            // zero.
            Some(F::ZERO)
        } else {
            // `idx`-th position is stored explicitly in `self.f`
            Some(self.bookkeping_table[idx])
        }
    }
}
