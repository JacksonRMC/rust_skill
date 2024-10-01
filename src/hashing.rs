#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use hex::ToHex;

use sp_core::*;

const HASH_SIZE: usize = 16;

pub fn hash_with_blake(data: &[u8]) -> [u8; HASH_SIZE] {
    blake2_128(data)
}

pub fn hash_with_twox(data: &[u8]) -> [u8; HASH_SIZE] {
    twox_128(data)
}

#[derive(Clone, PartialEq, Eq)]
pub enum HashAlgo {
    TwoX,
    Blake2,
}

pub fn hash_with(data: &[u8], algorithm: HashAlgo) -> [u8; HASH_SIZE] {
    match algorithm {
        HashAlgo::TwoX => hash_with_twox(data),
        HashAlgo::Blake2 => hash_with_blake(data),
    }
}

pub fn is_hash_preimage(hash: [u8; HASH_SIZE], data: &[u8], algorithm: HashAlgo) -> bool {
    match algorithm {
        HashAlgo::TwoX => hash == hash_with_twox(data),
        HashAlgo::Blake2 => hash == hash_with_blake(data),
    }
}

pub fn add_integrity_check(data: &[u8]) -> Vec<u8> {
    let mut new_image = hash_with(data, HashAlgo::Blake2).to_vec();
    let mut data_result = data.to_vec();
    data_result.extend(new_image);
    data_result
}

pub fn verify_data_integrity(data: Vec<u8>) -> Result<Vec<u8>, ()> {
    if data.len() < 16 {
        return Err(());
    }

    let initial_data = &data[..=17];
    let initial_preimage = &data[18..];
    let image = hash_with(initial_data, HashAlgo::Blake2).to_vec();

    if initial_preimage == image {
        Ok(initial_data.to_vec())
    } else {
        Err(())
    }
}

use rand::{rngs::SmallRng, seq::IteratorRandom, Rng, SeedableRng};
use std::{cell::RefCell, collections::HashMap};
use strum::{EnumIter, IntoEnumIterator};
type HashValue = [u8; HASH_SIZE];

/// Now that we are comfortable using hashes, let's implement a classic commit-reveal scheme using a
/// public message board. This message board implements some functionality to allow people to communicate.
/// It allows people to commit to a message, and then later reveal that message. It also lets people
/// look up a commitment to see if the message has been revealed or not.
///
/// This message board will use the 128-bit Blake2 hashing algorithm.
#[derive(Debug)]
pub struct PublicMessageBoard {
    /// The commitals to this public message board. A 'None' value represents a commitment that has
    /// not been revealed. A 'Some' value will contain the revealed value corresponding to the
    /// commitment.
    commitals: HashMap<HashValue, Option<String>>,
    /// A seeded RNG used to generate randomness for committing
    ///
    /// STUDENTS: DO NOT USE THIS YOURSELF. The provided code already uses it everywhere necessary.
    rng: SmallRng,
}
