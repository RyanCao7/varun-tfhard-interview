use crate::{mle::MultilinearExtension, utils::{SumcheckProof, UnivariateEvals}};
use shared_types::{transcript::TranscriptSponge, Field};

/// TODO: Fill out the `sumcheck_prove` function!
///
/// As a quick recap, recall that in sumcheck a prover wishes to convince a
/// verifier of a claim H = \sum_{b_1, ..., b_n} g(b_1, ..., b_n), where
/// * H is the prover-claimed sum.
/// * b_1, ..., b_n \in \{0, 1}^n is the boolean hypercube.
/// * g(x_1, ..., x_n) is, in general, a multivariate polynomial function.
///
/// Recall that in order to do this, the prover and verifier perform the
/// following exchange:
/// * The prover first sends the claimed sum H to the verifier.
/// * The prover and verifier then do the following `n` times:
///     * The prover sends the univariate polynomial
/// g_i(X) = \sum_{b_{i + 1}, ..., b_n} g(r_1, ..., r_{i - 1}, X, b_{i + 1}, ..., b_n).
///     * The verifier sends the challenge r_i, and checks that
/// g_i(r_i) = g_{i - 1}(0) + g_{i - 1}(1).
/// * Finally, the verifier receives an oracle evaluation of g(r_1, ..., r_n)
/// (in our case, it simply computes the evaluation on its own). It then checks
/// that g(r_1, ..., r_n) = g_n(r_n).
///
/// Note that:
/// * You do not have to implement the sumcheck verifier! We have already done
/// this for you.
/// * The form of g which we are given here is not an arbitrary multivariate
/// polynomial, but is instead the product of a set of multilinear extensions.
///     * In other words, g(x_1, ..., x_n) = \prod_k f_k(x_1, ..., x_{n_k}),
/// where n = \max_k(n_k) and the multilinear extensions may have different
/// numbers of variables within them.
///     * As an example, we might have
/// g(x_1, x_2, x_3) = f_1(x_1, x_2, x_3) * f_2(x_1, x_2).
/// * The form of the univariate polynomials which the prover must send is given
/// by the struct [UnivariateEvals]. Make sure that you are following this
/// convention!


/// Helper for \sum_{b \in {0,1}^n} \prod f_k(b) -- runs in O(|mles|*2^n) time
fn sum_over_hypercube<F: Field>(
    mles: &[MultilinearExtension<F>],
    n: usize,
) -> F {
    let total_points = 1usize << n;      //2^n points
    let mut final_sum = F::ZERO;

    // Enumerate each b \in {0,1}^n an integer idx. 
    for idx in 0..total_points {
       
        let mut prod = F::ONE;

        for f in mles {
            // number of variables in the current MLE
            let n_k = f.num_vars();       

            // drop the low (n - n_k) bits since they are not in this MLE
            let curr_mle_idx = idx >> (n - n_k);      
            
            prod *= f
                .get(curr_mle_idx)
                .unwrap();
        }
        final_sum += prod;
    }
    final_sum
}



/// Evaluate univariate polynomial \sum_{b}\prod f_k(r_1,r_2,X_i,b_i+1,...) and return the vector of evaluations.
fn eval_round_univariate<F: Field>(
    const_prod: F,  // product of inactive factors
    active_factors: &[(&Vec<F>, usize)],  // (table, vars_left) pairs still containing x_i
    num_remaining_vars: usize,
) -> Vec<F> {

    // Number of remaining points (b_i+1, ... b_n) =  2^{num_remaining_vars}
    let num_remaining_pts  = 1usize << num_remaining_vars;

    // Number of non-constant factors -- also the degree of X_i
    let d_i   = active_factors.len(); 

    let mut evals = Vec::with_capacity(d_i + 1);

    // Evaluate for alpha in [d_i] -- O(d_i^2 2^{n-i-1}) time
    for alpha in 0..=d_i {

        let a = F::from(alpha as u64);
        let mut sum = F::ZERO;

        for point in 0..num_remaining_pts {

            let mut prod = const_prod;

            // multiply by each active_factor evaluated at (x_i = a, point).
            for (tab, v_left) in active_factors {

                // vars after x_i in this MLE
                let num_remaining_vars_in_mle = v_left - 1; 

                // drop these bits
                let shift      = num_remaining_vars - num_remaining_vars_in_mle;   

                // index into MLE table
                let base_idx   = point >> shift;  

                // 2^{num_remaining_vars_in_mle‑1}
                let half_sz    = 1usize << num_remaining_vars_in_mle;

                // Use fact f(a, b_2, ..., b_n) = (1 - a) * f(0, b_2, ..., b_n) + a * f(1, b_2, ..., b_n)
                let low  = tab[base_idx];
                let high = tab[base_idx + half_sz];
                prod *= (F::ONE - a) * low + a * high;
            }
            sum += prod;
        }
        evals.push(sum);
    }
    evals
}

/// In‑place update of every active table after receiving verifier challenge r_i.
fn restrict_all_active_tables<F: Field>(tables: &mut [Vec<F>], vars_left: &mut [usize], r_i: F) {
    for (tab, v_left) in tables.iter_mut().zip(vars_left) {
        if *v_left > 0 {
            MultilinearExtension::restrict_first_var(tab, r_i);
            *v_left -= 1;
        }
    }
}



fn sumcheck_prove<F: Field>(
    transcript: &mut impl TranscriptSponge<F>,
    mles: &[MultilinearExtension<F>],
) -> SumcheckProof<F> {

    // Maximum number of variables across all MLE factors 
    let n = mles.iter().map(|f| f.num_vars()).max().unwrap_or(0);

    // Clone bookkeeping tables
    let mut tables: Vec<Vec<F>> = mles.iter().map(|f| f.table().to_vec()).collect();

    // Vector to store number of variables left in each MLE - initialized to f.num_vars()
    let mut vars_left: Vec<usize> = mles.iter().map(|f| f.num_vars()).collect();

    // Compute the Claimed Sum
    let claimed = sum_over_hypercube::<F>(mles, n); 
    transcript.absorb(claimed);

    let mut prover_msgs = Vec::with_capacity(n);


    // Tracks the constant MLEs once all their variables have been initialized
    let mut const_prod = F::ONE;  
    
    for i in 0..n {

        // Number of remaining variable x_j for j > i
        let num_remaining_vars = n - i - 1;                 

        // Collect all active factors (those with vars_left > 0)
        let active_factors: Vec<(&Vec<F>, usize)> = tables
            .iter()
            .zip(&vars_left)
            .filter(|(_, &v)| v > 0)
            .map(|(t, &v)| (t, v))
            .collect();

        // Compute evaluations of g_i. 
        let evals = eval_round_univariate::<F>(const_prod, &active_factors, num_remaining_vars);
        transcript.absorb_elements(&evals);
        prover_msgs.push(UnivariateEvals::new(evals.clone()));

        // Get verifier challenge r_i and update tables.
        let r_i = transcript.squeeze();

        let prev_vars_left = vars_left.clone();

        // Update every active table
        restrict_all_active_tables::<F>(&mut tables, &mut vars_left, r_i);

        // Update the constant factors from tables that became inactive in this round
        for ((tab, v), prev_v) in tables.iter().zip(&vars_left).zip(prev_vars_left.iter()) {
            if *prev_v > 0 && *v == 0 {
                const_prod *= tab[0];
            }
        }
    }

    SumcheckProof::new(claimed, prover_msgs)
}

fn sumcheck_verify<F: Field>(
    transcript: &mut impl TranscriptSponge<F>,
    sumcheck_proof: SumcheckProof<F>,
    oracle_query: F,
) -> bool {
    transcript.absorb(sumcheck_proof.get_claimed_sum());
    let mut idx = 0;

    let mut expected_evaluation = sumcheck_proof.get_claimed_sum();
    for prover_message in sumcheck_proof.get_prover_sumcheck_round_messages() {
        let raw_evals = prover_message.get_raw_evals();
        transcript.absorb_elements(&raw_evals);
        if (raw_evals[0] + raw_evals[1]) != expected_evaluation {
            dbg!("Failed sumcheck at round: ", idx);
            return false;
        }
        idx += 1;
        let evaluation_point = transcript.squeeze();
        expected_evaluation = prover_message
            .evaluate_at_a_point(evaluation_point)
            .unwrap();
    }

    if expected_evaluation != oracle_query {
        dbg!(expected_evaluation.to_bytes_le());
        dbg!("Failed oracle query eval");
        return false;
    }
    true
}

mod tests {
    use crate::{
        mle::MultilinearExtension,
        sumcheck::{sumcheck_prove, sumcheck_verify},
    };
    use ark_std::{rand::Rng, test_rng};
    use shared_types::{transcript::poseidon_sponge::PoseidonSponge, Fr, HasByteRepresentation};

    fn generate_random_mle_with_num_vars(
        rng: &mut impl Rng,
        num_vars: usize,
    ) -> MultilinearExtension<Fr> {
        let random_mle_vec = (0..(1 << num_vars))
            .map(
                |_| Fr::from(rng.gen::<u64>()), // Fr::one()
            )
            .collect();
        MultilinearExtension::new(random_mle_vec)
    }

    #[test]
    fn test_single_mle() {
        const NUM_VARS: usize = 3;
        let mut rng = test_rng();
        let mle = generate_random_mle_with_num_vars(&mut rng, NUM_VARS);
        let mut prover_transcript = PoseidonSponge::default();

        let proof = sumcheck_prove(&mut prover_transcript, &[mle.clone()]);
        let mut verifier_transcript = PoseidonSponge::default();
        let final_eval_bytes = [
            158, 56, 104, 198, 155, 67, 60, 11, 72, 181, 184, 46, 117, 152, 139, 250, 227, 221,
            108, 134, 224, 100, 230, 19, 145, 127, 196, 135, 50, 236, 235, 29,
        ];
        let oracle_query = Fr::from_bytes_le(&final_eval_bytes);
        assert!(sumcheck_verify(
            &mut verifier_transcript,
            proof,
            oracle_query
        ));
    }

    #[test]
    fn test_multiple_mle_same_num_vars() {
        const NUM_VARS_MLE_1: usize = 3;
        const NUM_VARS_MLE_2: usize = 3;
        let mut rng = test_rng();
        let mle_1 = generate_random_mle_with_num_vars(&mut rng, NUM_VARS_MLE_1);
        let mle_2 = generate_random_mle_with_num_vars(&mut rng, NUM_VARS_MLE_2);
        let mut prover_transcript = PoseidonSponge::default();

        let proof = sumcheck_prove(&mut prover_transcript, &[mle_1.clone(), mle_2.clone()]);
        let mut verifier_transcript = PoseidonSponge::default();

        let final_eval_bytes = [
            124, 144, 96, 196, 109, 76, 243, 146, 123, 238, 61, 40, 84, 231, 51, 165, 224, 88, 33,
            242, 188, 135, 118, 43, 66, 182, 89, 89, 241, 253, 53, 47,
        ];
        let oracle_query = Fr::from_bytes_le(&final_eval_bytes);
        assert!(sumcheck_verify(
            &mut verifier_transcript,
            proof,
            oracle_query,
        ));
    }

    #[test]
    fn test_multiple_mle_diff_num_vars() {
        const NUM_VARS_MLE_1: usize = 3;
        const NUM_VARS_MLE_2: usize = 2;
        let mut rng = test_rng();
        let mle_1 = generate_random_mle_with_num_vars(&mut rng, NUM_VARS_MLE_1);
        let mle_2 = generate_random_mle_with_num_vars(&mut rng, NUM_VARS_MLE_2);
        let mut prover_transcript = PoseidonSponge::default();

        let proof = sumcheck_prove(&mut prover_transcript, &[mle_1.clone(), mle_2.clone()]);
        let mut verifier_transcript = PoseidonSponge::default();

        let final_eval_bytes = [
            181, 127, 104, 99, 220, 104, 30, 186, 9, 88, 85, 75, 164, 140, 2, 133, 151, 203, 2,
            158, 58, 173, 19, 46, 90, 224, 207, 221, 208, 143, 249, 14,
        ];
        let oracle_query = Fr::from_bytes_le(&final_eval_bytes);
        assert!(sumcheck_verify(
            &mut verifier_transcript,
            proof,
            oracle_query
        ))
    }

    /// This test runs the sumcheck verifier on a sumcheck proof of the claimed
    /// sum over a single multilinear extension.
    ///
    /// The oracle query in the verifier is intentionally incorrect to test whether
    /// the implementation is sound (correctly identifies false proofs).
    #[test]
    #[should_panic]
    fn test_implementation_soundness() {
        const NUM_VARS_MLE_1: usize = 3;
        let mut rng = test_rng();
        let mle_1 = generate_random_mle_with_num_vars(&mut rng, NUM_VARS_MLE_1);
        let mut prover_transcript = PoseidonSponge::default();
    
        let proof = sumcheck_prove(&mut prover_transcript, &[mle_1.clone()]);
        let mut verifier_transcript = PoseidonSponge::default();
    
        let final_eval_bytes = [
            127, 127, 104, 99, 220, 104, 30, 186, 9, 88, 85, 75, 164, 140, 2, 133, 151, 203, 2,
            158, 58, 173, 19, 46, 90, 224, 207, 221, 208, 104, 249, 14,
        ];
        let oracle_query = Fr::from_bytes_le(&final_eval_bytes);
        assert!(sumcheck_verify(
            &mut verifier_transcript,
            proof,
            oracle_query
        ))
    }
}
