//! Write a Merkle tree implementation that supports proofs and multiproofs.

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use hex::encode;
use rand::SeedableRng;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    mem,
};

/// We'll use Rust's built-in hashing which returns a u64 type.
/// This alias just helps us understand when we're treating the number as a hash
pub type HashValue = u64;

/// Helper function that makes the hashing interface easier to understand.
pub fn hash<T: Hash>(t: &T) -> HashValue {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Given a vector of data blocks this function adds padding blocks to the end
/// until the length is a power of two which is needed for Merkle trees.
/// The padding value should be the empty string "".
pub fn pad_base_layer(blocks: &mut Vec<&str>) {
    let mut blength = blocks.len();
    while !((blength != 0) && ((blength & (blength - 1)) == 0)) {
        blocks.push("");
        blength += 1;
    }
}

/// Helper function to combine two hashes and compute the hash of the combination.
/// This will be useful when building the intermediate nodes in the Merkle tree.
///
/// Our implementation will hex-encode the hashes (as little-endian uints) into strings, concatenate
/// the strings, and then hash that string.
pub fn concatenate_hash_values(left: HashValue, right: HashValue) -> HashValue {
    let left_by = hex::encode(left.to_le_bytes());
    let right_by = hex::encode(right.to_le_bytes());

    let combined = left_by + &right_by;
    hash(&combined)
}

/// Calculates the Merkle root of a sentence. We consider each word in the sentence to
/// be one block. Words are separated by one or more spaces.
///
/// Example:
/// Sentence: "You trust me, right?"
/// "You", "trust", "me," "right?"
/// Notice that the punctuation like the comma and exclamation point are included in the words
/// but the spaces are not.
pub fn calculate_merkle_root(sentence: &str) -> HashValue {
    let mut padded = sentence.split_whitespace().collect();
    pad_base_layer(&mut padded);

    let mut leaf_hashes: Vec<HashValue> =
        padded.clone().into_iter().map(|word| hash(&word)).collect();
    let mut work = vec![];
    let mut i: usize = 0;

    while leaf_hashes.len() != i {
        let mut current_node_info = concatenate_hash_values(leaf_hashes[i], leaf_hashes[i + 1]);
        work.push(current_node_info);
        i += 2;

        if leaf_hashes.len() == i && work.len() > 1 {
            leaf_hashes = work;
            work = vec![];
            i = 0;
        }
    }

    work[0]
}

/// A representation of a sibling node along the Merkle path from the data
/// to the root. It is necessary to specify which side the sibling is on
/// so that the hash values can be combined in the same order.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SiblingNode {
    Left(HashValue),
    Right(HashValue),
}

/// A proof is just an alias for a vec of sibling nodes.
pub type MerkleProof = Vec<SiblingNode>;

/// Generates a Merkle proof that one particular word is contained
/// in the given sentence. You provide the sentence and the index of the word
/// which you want a proof.
///
/// Panics if the index is beyond the length of the sentence.
///
/// Example: I want to prove that the word "trust" is in the sentence "You trust me, right?"
/// So I call generate_proof("You trust me, right?", 1)
/// And I get back the merkle root and list of intermediate nodes from which the
/// root can be reconstructed.
pub fn generate_proof(sentence: &str, index: usize) -> (HashValue, MerkleProof) {
    let mut sig_word = sentence.split_whitespace().collect::<Vec<&str>>();
    pad_base_layer(&mut sig_word);

    if index >= sig_word.len() {
        panic!("Index out of bounds");
    }

    let mut trusted_word = sig_word[index];
    let mut node_vector = vec![];

    let mut i: usize = 0;
    let mut is_left: bool = true;

    while sig_word.len() > i {
        let mut combo_nodes = concatenate_hash_values(hash(&sig_word[i]), hash(&sig_word[i + 1]));

        if trusted_word == sig_word[i] {
            combo_nodes = hash(&sig_word[i + 1]);
        } else if trusted_word == sig_word[i + 1] {
            combo_nodes = hash(&sig_word[i]);
        }

        if is_left {
            node_vector.push(SiblingNode::Left(combo_nodes));
        } else {
            node_vector.push(SiblingNode::Right(combo_nodes));
        }

        i += 2;
        is_left = !is_left;
    }

    (calculate_merkle_root(&sentence), node_vector)
}

/// Checks whether the given word is contained in a sentence, without knowing the whole sentence.
/// Rather we only know the merkle root of the sentence and a proof.
pub fn validate_proof(root: &HashValue, word: &str, proof: MerkleProof) -> bool {
    let mut initial_value = hash(&word);
    let mut value = proof[0].clone();

    let mut root_hash_prove = match value {
        SiblingNode::Left(hash_value) => concatenate_hash_values(hash_value, initial_value),
        SiblingNode::Right(hash_value) => concatenate_hash_values(initial_value, hash_value),
    };

    let mut i: usize = 1;

    while proof.len() > i {
        root_hash_prove = match proof[i] {
            SiblingNode::Left(hash_value) => concatenate_hash_values(hash_value, root_hash_prove),
            SiblingNode::Right(hash_value) => concatenate_hash_values(root_hash_prove, hash_value),
        };

        i += 1;
    }

    &root_hash_prove == root
}

/// A compact Merkle multiproof is used to prove multiple entries in a Merkle tree in a highly
/// space-efficient manner.
#[derive(Debug, PartialEq, Eq)]
pub struct CompactMerkleMultiProof {
    // The indices requested in the initial proof generation
    pub leaf_indices: Vec<usize>,
    // The additional hashes necessary for computing the proof, given in order from
    // lower to higher index, lower in the tree to higher in the tree.
    pub hashes: Vec<HashValue>,
}

/// Generate a compact multiproof that some words are contained in the given sentence. Returns the
/// root of the merkle tree, and the compact multiproof. You provide the words at `indices` in the
/// same order as within `indices` to verify the proof. `indices` is not necessarily sorted.
///
/// Panics if any index is beyond the length of the sentence, or any index is duplicated.
///
/// ## Explanation
///
/// To understand the compaction in a multiproof, see the following merkle tree. To verify a proof
/// for the X's, only the entries marked with H are necessary. The rest can be calculated. Then, the
/// hashes necessary are ordered based on the access order. The H's in the merkle tree are marked
/// with their index in the output compact proof.
///
/// ```text
///                                      O            
///                                   /     \           
///                                O           O     
///                              /   \       /   \     
///                             O    H_1   H_2    O  
///                            / \   / \   / \   / \
///                           X  X  O  O  O  O  X  H_0
///
///     
/// ```
///
/// The proof generation process would proceed similarly to a normal merkle proof generation, but we
/// need to keep track of which hashes are known to the verifier by a certain height, and which need
/// to be given to them.
/// PBA_Berkeley
/// In the leaf-node layer, the first pair of hashes are both
/// known, and so no extra data is needed to go up the tree.  In the next two pairs of hashes,
/// neither are known, and so the verifier does not need them. In the last set, the verifier only
/// knows the left hash, and so the right hash must be provided.
///
/// In the second layer, the first and fourth hashes are known. The first pair is missing the right
/// hash, which must be included in the proof. The second pair is missing the left hash, which also
/// must be included.
///
/// In the final layer before the root, both hashes are known to the verifier, and so no further
/// proof is needed.
///
/// The final proof for this example would be
/// ```ignore
/// CompactMerkleMultiProof {
///     leaf_indices: [0, 1, 6],
///     hashes: [H_0, H_1, H_2]
/// }
/// ```
pub fn generate_compact_multiproof(
    sentence: &str,
    indices: Vec<usize>,
) -> (HashValue, CompactMerkleMultiProof) {
    let mut sig_word = sentence.split_whitespace().collect::<Vec<&str>>();
    pad_base_layer(&mut sig_word);

    if indices.iter().any(|x| x > &sig_word.len()) {
        panic!("Index out of bounds");
    }

    let mut leaf_indices = vec![];
    let mut hashes = vec![];
    let mut undetermined = vec![];

    let mut i: usize = 0;
    let mut is_left: bool = true;

    let mut secondary = false;

    while sig_word.len() > i {
        let mut combo_nodes = concatenate_hash_values(hash(&sig_word[i]), hash(&sig_word[i + 1]));

        if indices.contains(&i) && indices.contains(&(&i + 1)) {
            leaf_indices.push(i);
            leaf_indices.push(i + 1);
        } else if !indices.contains(&i) && !indices.contains(&(&i + 1)) {
            undetermined.push(combo_nodes);
        } else if indices.contains(&i) || indices.contains(&(&i + 1)) {
            if indices.contains(&i) {
                leaf_indices.push(i);
                combo_nodes = hash(&sig_word[i + 1]);
            }

            if indices.contains(&(&i + 1)) {
                leaf_indices.push(i + 1);
                combo_nodes = hash(&sig_word[i]);
            }

            hashes.push(combo_nodes);
        }

        i += 2;
        is_left = !is_left;
    }

    for hex in undetermined {
        hashes.push(hex);
    }

    (
        calculate_merkle_root(&sentence),
        CompactMerkleMultiProof {
            leaf_indices,
            hashes,
        },
    )
}

/// Validate a compact merkle multiproof to check whether a list of words is contained in a sentence, based on the merkle root of the sentence.
/// The words must be in the same order as the indices passed in to generate the multiproof.
/// Duplicate indices in the proof are rejected by returning false.
pub fn validate_compact_multiproof(
    root: &HashValue,
    words: Vec<&str>,
    proof: CompactMerkleMultiProof,
) -> bool {
    let mut inital_hashes: Vec<u64> = vec![];
    let mut new_vec: Vec<u64> = vec![];

    let mut new_order: Vec<u64> = proof
        .hashes
        .clone()
        .into_iter()
        .rev()
        .map(|x| x as u64)
        .collect();

    let six_element = concatenate_hash_values(hash(&words[2]), proof.hashes[0]);
    let fir_two_words = concatenate_hash_values(hash(&words[0]), hash(&words[1]));

    let middle_row_1 = concatenate_hash_values(fir_two_words, proof.hashes[1]);
    let middle_row_2 = concatenate_hash_values(proof.hashes[2], six_element);

    let root_test = concatenate_hash_values(middle_row_1, middle_row_2);

    // Check to see

    let mut i: usize = 0;
    let mut is_left: bool = true;
    let mut word_count = 0;
    let mut useful_indeex: Vec<usize> = vec![];
    let mut eex: Vec<usize> = vec![];

    while proof.leaf_indices.len() > i {
        let leaf_deal = proof.leaf_indices[*&i];
        let word = words[*&i];
        let mut pair = i + 1 != proof.leaf_indices.len()
            && proof.leaf_indices[*&i] + 1 == proof.leaf_indices[*&i + 1];

        let mut combo_nodes = 0;

        if pair && is_left {
            combo_nodes = concatenate_hash_values(hash(&words[i]), hash(&words[i + 1]));
            println!(
                "FIRST TWO WORDS:\n{:?}\n{:?}\n\n",
                combo_nodes, fir_two_words
            );
            new_vec.push(combo_nodes);

            i += 2;
        } else {
            let proof_hash = new_order.pop().unwrap();

            if is_left {
                combo_nodes = concatenate_hash_values(proof_hash, hash(&words[i]));
            } else {
                combo_nodes = concatenate_hash_values(hash(&words[i]), proof_hash);
            }

            println!("ELement_6:\n{:?}\n{:?}\n\n", combo_nodes, six_element);
            new_vec.push(combo_nodes);
            i += 1;
            word_count += 1;

            eex.push(proof_hash.try_into().unwrap());
            useful_indeex.push(leaf_deal);
        }

        if i % 2 == 0 {
            is_left = !is_left;
        }
    }

    i = 0;
    is_left = true;

    let mut leave_it_here: Vec<u64> = vec![];

    let mut hash_proof: Vec<u64> = new_order.clone();
    let mut computed_hash: Vec<u64> = new_vec
        .clone()
        .into_iter()
        .rev()
        .map(|x| x as u64)
        .collect();

    let mut index_revers: Vec<u64> = useful_indeex
        .clone()
        .into_iter()
        .rev()
        .map(|x| x as u64)
        .collect();

    while hash_proof.len() > 0 {
        let proof_hashes = hash_proof.pop().unwrap();
        let computed_h = computed_hash.pop().unwrap();

        let leaf_index = index_revers.pop().unwrap_or(0) / 2;

        is_left = leaf_index == 0 || leaf_index % 2 == 0;

        if is_left {
            leave_it_here.push(concatenate_hash_values(proof_hashes, computed_h));
        } else {
            leave_it_here.push(concatenate_hash_values(computed_h, proof_hashes));
        }

        if computed_hash.len() == 0 {
            computed_hash = leave_it_here
                .clone()
                .into_iter()
                .rev()
                .map(|x| x as u64)
                .collect();
        }
    }

    &concatenate_hash_values(leave_it_here[0], leave_it_here[1]) == root
}

// Now that we have a normal and compact method to generate proofs, let's compare how
// space-efficient the two are. The two functions below will be helpful for answering the questions
// in the readme.

/// Generate a space-separated string of `n` random 4-letter words. Use of this function is not
/// mandatory.
pub fn string_of_random_words(n: usize) -> String {
    let mut ret = String::new();
    for i in 0..n {
        ret.push_str(random_word::gen_len(4).unwrap());
        if i != n - 1 {
            ret.push(' ');
        }
    }
    ret
}

/// Given a string of words, and the length of the words from which to generate proofs, generate
/// proofs for `num_proofs` random indices in `[0, length)`.  Uses `rng_seed` as the rng seed, if
/// replicability is desired.
///
/// Return the size of the compact multiproof, and then the combined size of the standard merkle proofs.
///
/// This function assumes the proof generation is correct, and does not validate them.
pub fn compare_proof_sizes(
    words: &str,
    length: usize,
    num_proofs: usize,
    rng_seed: u64,
) -> (usize, usize) {
    assert!(
        num_proofs <= length,
        "Cannot make more proofs than available indices!"
    );

    let mut rng = rand::rngs::SmallRng::seed_from_u64(rng_seed);
    let indices = rand::seq::index::sample(&mut rng, length, num_proofs).into_vec();
    let (_, compact_proof) = generate_compact_multiproof(words, indices.clone());
    // Manually calculate memory sizes
    let compact_size = mem::size_of::<usize>() * compact_proof.leaf_indices.len()
        + mem::size_of::<HashValue>() * compact_proof.hashes.len()
        + mem::size_of::<Vec<usize>>() * 2;

    let mut individual_size = 0;
    for i in indices {
        let (_, proof) = generate_proof(words, i);
        individual_size +=
            mem::size_of::<Vec<usize>>() + mem::size_of::<SiblingNode>() * proof.len();
    }

    (compact_size, individual_size)
}

/// An answer to the below short answer problems
#[derive(PartialEq, Debug)]
pub struct ShortAnswer {
    /// The answer to the problem
    pub answer: usize,
    /// The explanation associated with an answer. This should be 1-3 sentences. No need to make it
    /// too long!
    pub explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_base_layer_sanity_check() {
        let mut data = vec!["a", "b", "c"];
        let expected = vec!["a", "b", "c", ""];
        pad_base_layer(&mut data);
        assert_eq!(expected, data);
    }

    #[test]
    fn concatenate_hash_values_sanity_check() {
        let left = hash(&"a");
        let right = hash(&"b");
        assert_eq!(13491948173500414413, concatenate_hash_values(left, right));
    }

    #[test]
    fn calculate_merkle_root_sanity_check() {
        let sentence = "You trust me, right?";
        assert_eq!(4373588283528574023, calculate_merkle_root(sentence));
    }

    #[test]
    fn proof_generation_sanity_check() {
        let sentence = "You trust me, right?";
        let expected = (
            4373588283528574023,
            vec![
                SiblingNode::Left(4099928055547683737),
                SiblingNode::Right(2769272874327709143),
            ],
        );
        assert_eq!(expected, generate_proof(sentence, 1));
    }

    #[test]
    fn validate_proof_sanity_check() {
        let word = "trust";
        let root = 4373588283528574023;
        let proof = vec![
            SiblingNode::Left(4099928055547683737),
            SiblingNode::Right(2769272874327709143),
        ];
        assert!(validate_proof(&root, word, proof));
    }

    #[test]
    fn generate_compact_multiproof_sanity_check() {
        let sentence = "Here's an eight word sentence, special for you.";
        let indices = vec![0, 1, 6];
        let expected = (
            14965309246218747603,
            CompactMerkleMultiProof {
                leaf_indices: vec![0, 1, 6],
                hashes: vec![
                    1513025021886310739,
                    7640678380001893133,
                    5879108026335697459,
                ],
            },
        );
        assert_eq!(expected, generate_compact_multiproof(sentence, indices));
    }

    #[test]
    fn validate_compact_multiproof_sanity_check() {
        let proof = (
            14965309246218747603u64,
            CompactMerkleMultiProof {
                leaf_indices: vec![0, 1, 6],
                hashes: vec![
                    1513025021886310739,
                    7640678380001893133,
                    5879108026335697459,
                ],
            },
        );
        let words = vec!["Here's", "an", "for"];
        assert_eq!(true, validate_compact_multiproof(&proof.0, words, proof.1));
    }

    #[test]
    fn short_answer_1_has_answer() {
        assert_ne!(
            ShortAnswer {
                answer: 0,
                explanation: "".to_string(),
            },
            short_answer_1()
        )
    }

    #[test]
    fn short_answer_2_has_answer() {
        assert_ne!(
            ShortAnswer {
                answer: 0,
                explanation: "".to_string(),
            },
            short_answer_2()
        )
    }
}
