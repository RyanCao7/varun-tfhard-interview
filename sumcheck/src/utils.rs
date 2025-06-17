use anyhow::{anyhow, Result};
use shared_types::Field;

/// A sumcheck proof consists of:
/// * Prover-claimed sum over the hypercube, i.e. \sum_{b_1, ..., b_n} f(b_1, ..., b_n)
/// * Univariate polynomial \sum_{b_{i + 1}, ..., b_n} f(r_1, ..., r_{i - 1}, X, b_{i + 1}, ..., b_n)
/// for the ith round.
pub struct SumcheckProof<F: Field> {
    claimed_sum: F,
    prover_sumcheck_round_messages: Vec<UnivariateEvals<F>>,
}

impl<F: Field> SumcheckProof<F> {
    pub fn new(claimed_sum: F, prover_sumcheck_round_messages: Vec<UnivariateEvals<F>>) -> Self {
        Self {
            claimed_sum,
            prover_sumcheck_round_messages,
        }
    }

    pub fn get_claimed_sum(&self) -> F {
        self.claimed_sum
    }

    pub fn get_prover_sumcheck_round_messages(&self) -> Vec<UnivariateEvals<F>> {
        self.prover_sumcheck_round_messages.clone()
    }
}

/// Basic structure of a univariate polynomial, as defined by its evaluations
/// f(0), f(1), ..., f(d) for a degree-d polynomial.
#[derive(Clone, Debug)]
pub struct UnivariateEvals<F: Field> {
    evals: Vec<F>,
    univariate_poly_deg: usize,
}

impl<F: Field> UnivariateEvals<F> {
    /// Constructor. Will automatically infer the polynomial degree.
    pub fn new(evals: Vec<F>) -> Self {
        assert!(evals.len() > 0);
        Self {
            univariate_poly_deg: evals.len() - 1,
            evals,
        }
    }

    pub fn get_raw_evals(&self) -> Vec<F> {
        self.evals.clone()
    }

    pub fn get_degree(&self) -> usize {
        self.univariate_poly_deg
    }

    /// Use degree + 1 evaluations to figure out the evaluation at some arbitrary
    /// point
    pub fn evaluate_at_a_point(&self, point: F) -> Result<F> {
        // Special case for the constant polynomial.
        if self.evals.len() == 1 {
            return Ok(self.evals[0]);
        }

        debug_assert!(self.evals.len() > 1);

        // Special cases for `point == 0` and `point == 1`.
        if point == F::ZERO {
            return Ok(self.evals[0]);
        }
        if point == F::ONE {
            return Ok(*self.evals.get(1).unwrap_or(&self.evals[0]));
        }

        // Need degree + 1 evaluations to interpolate
        let eval = (0..self.evals.len())
            .map(
                // Create an iterator of everything except current value
                |x| {
                    (0..x)
                        .chain(x + 1..self.evals.len())
                        .map(|x| F::from(x as u64))
                        .fold(
                            // Compute vector of (numerator, denominator)
                            (F::ONE, F::ONE),
                            |(num, denom), val| {
                                (num * (point - val), denom * (F::from(x as u64) - val))
                            },
                        )
                },
            )
            .enumerate()
            .map(
                // Add up barycentric weight * current eval at point
                |(x, (num, denom))| self.evals[x] * num * denom.invert().unwrap(),
            )
            .reduce(|x, y| x + y);
        eval.ok_or(anyhow!("Interpretation Error: No Inverse"))
    }
}
