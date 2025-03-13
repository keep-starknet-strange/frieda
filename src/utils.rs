//! Utilities module
//!
//! This module provides utility functions for the FRIEDA library,
//! including Merkle tree implementation, hashing, and serialization.

use crate::{FriedaError, Result, M31};
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};

/// Converts an M31 field element to bytes
///
/// # Arguments
///
/// * `value` - The field element to convert
///
/// # Returns
///
/// A 4-byte array representing the field element
pub fn m31_to_bytes(value: M31) -> [u8; 4] {
    // In stwo-prover, M31 doesn't have direct conversion to u32
    // We'll need to implement this differently
    let val = value.to_string().parse::<u32>().unwrap_or(0);
    val.to_le_bytes()
}

/// Converts bytes to an M31 field element
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
///
/// # Returns
///
/// An M31 field element
pub fn bytes_to_m31(bytes: &[u8; 4]) -> M31 {
    let val = u32::from_le_bytes(*bytes);
    M31::from(val)
}

/// Hashes a message using the SHA-256 algorithm
///
/// # Arguments
///
/// * `message` - The message to hash
///
/// # Returns
///
/// A 32-byte array containing the hash
pub fn hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    result.into()
}

/// Hashes two child nodes together to produce a parent node in a Merkle tree
///
/// # Arguments
///
/// * `left` - The left child hash
/// * `right` - The right child hash
///
/// # Returns
///
/// The hash of the concatenation of the left and right children
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    result.into()
}

/// A Merkle tree implementation
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The levels of the tree, with each level containing the hashes of the nodes at that level
    /// The bottom level (leaves) is at index 0, and the root is at the last index
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Creates a new Merkle tree from the given leaves
    ///
    /// # Arguments
    ///
    /// * `leaves` - The leaf values of the tree
    ///
    /// # Returns
    ///
    /// A new Merkle tree
    pub fn new(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![[0; 32]]],
            };
        }

        let mut levels = Vec::new();
        levels.push(leaves.to_vec());

        let mut current_level = 0;
        while levels[current_level].len() > 1 {
            let level_below = &levels[current_level];
            let mut current_level_hashes = Vec::new();

            // Iterate over pairs of nodes in the level below
            for i in (0..level_below.len()).step_by(2) {
                if i + 1 < level_below.len() {
                    // Hash the pair of nodes
                    let hash = hash_pair(&level_below[i], &level_below[i + 1]);
                    current_level_hashes.push(hash);
                } else {
                    // If there's an odd number of nodes, duplicate the last one
                    let hash = hash_pair(&level_below[i], &level_below[i]);
                    current_level_hashes.push(hash);
                }
            }

            levels.push(current_level_hashes);
            current_level += 1;
        }

        Self { levels }
    }

    /// Gets the root of the Merkle tree
    ///
    /// # Returns
    ///
    /// The root hash of the tree
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    /// Gets the authentication path for a leaf in the Merkle tree
    ///
    /// # Arguments
    ///
    /// * `leaf_index` - The index of the leaf
    ///
    /// # Returns
    ///
    /// The authentication path (sibling hashes) from the leaf to the root
    pub fn get_auth_path(&self, leaf_index: usize) -> Result<Vec<[u8; 32]>> {
        if leaf_index >= self.levels[0].len() {
            return Err(FriedaError::InvalidInput(format!(
                "Leaf index {} is out of bounds",
                leaf_index
            )));
        }

        let mut path = Vec::new();
        let mut index = leaf_index;

        for level in 0..self.levels.len() - 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if sibling_index < self.levels[level].len() {
                path.push(self.levels[level][sibling_index]);
            } else {
                // If there's no sibling, use the node itself
                path.push(self.levels[level][index]);
            }

            // Move to the parent's index in the next level
            index /= 2;
        }

        Ok(path)
    }

    /// Verifies that a leaf value is included in the Merkle tree
    ///
    /// # Arguments
    ///
    /// * `leaf` - The leaf value
    /// * `leaf_index` - The index of the leaf
    /// * `auth_path` - The authentication path
    /// * `root` - The root hash
    ///
    /// # Returns
    ///
    /// `true` if the leaf is included in the tree, `false` otherwise
    pub fn verify_inclusion(
        leaf: &[u8; 32],
        leaf_index: usize,
        auth_path: &[[u8; 32]],
        root: &[u8; 32],
    ) -> bool {
        let mut current_hash = *leaf;
        let mut index = leaf_index;

        for sibling in auth_path {
            // Determine whether the current node is a left or right child
            if index % 2 == 0 {
                // Current node is a left child, so sibling is on the right
                current_hash = hash_pair(&current_hash, sibling);
            } else {
                // Current node is a right child, so sibling is on the left
                current_hash = hash_pair(sibling, &current_hash);
            }

            // Move to the parent's index
            index /= 2;
        }

        current_hash == *root
    }
}

/// Creates leaf nodes for a Merkle tree from a batch of field elements
///
/// # Arguments
///
/// * `values` - The field elements
///
/// # Returns
///
/// A vector of hashed leaf nodes
pub fn create_leaf_nodes(values: &[M31]) -> Vec<[u8; 32]> {
    values
        .iter()
        .map(|value| {
            let bytes = m31_to_bytes(*value);
            hash(&bytes)
        })
        .collect()
}

/// Creates a Merkle tree from a batch of field elements
///
/// # Arguments
///
/// * `values` - The field elements
///
/// # Returns
///
/// A Merkle tree
pub fn create_merkle_tree(values: &[M31]) -> MerkleTree {
    let leaves = create_leaf_nodes(values);
    MerkleTree::new(&leaves)
}

/// Batch an array of M31 field elements
///
/// # Arguments
///
/// * `values` - The field elements to batch
/// * `batch_size` - The size of each batch
///
/// # Returns
///
/// A vector of batched field elements, where each batch contains `batch_size` elements
pub fn batch_values(values: &[M31], batch_size: usize) -> Vec<Vec<M31>> {
    if batch_size == 1 {
        return values.iter().map(|&v| vec![v]).collect();
    }

    let mut batched = Vec::new();
    for i in (0..values.len()).step_by(batch_size) {
        let mut batch = Vec::new();
        for j in 0..batch_size {
            if i + j < values.len() {
                batch.push(values[i + j]);
            } else {
                batch.push(M31::default()); // Pad with zeros if necessary
            }
        }
        batched.push(batch);
    }

    batched
}

/// Flattens a vector of batched field elements
///
/// # Arguments
///
/// * `batched` - The batched field elements
///
/// # Returns
///
/// A flattened vector of field elements
pub fn unbatch_values(batched: &[Vec<M31>]) -> Vec<M31> {
    let mut flattened = Vec::new();
    for batch in batched {
        flattened.extend_from_slice(batch);
    }
    flattened
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m31_conversion() {
        let value = M31::from(42);
        let bytes = m31_to_bytes(value);
        let recovered = bytes_to_m31(&bytes);
        assert_eq!(value, recovered);
    }

    #[test]
    fn test_hash() {
        let message = b"Hello, world!";
        let hash1 = hash(message);
        let hash2 = hash(message);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_merkle_tree() {
        let values = vec![M31::from(1), M31::from(2), M31::from(3), M31::from(4)];

        let leaves = create_leaf_nodes(&values);
        let tree = MerkleTree::new(&leaves);

        // Get the authentication path for leaf 2
        let auth_path = tree.get_auth_path(2).unwrap();

        // Verify that leaf 2 is included in the tree
        assert!(MerkleTree::verify_inclusion(
            &leaves[2],
            2,
            &auth_path,
            &tree.root()
        ));
    }

    #[test]
    fn test_batch_values() {
        let values = vec![
            M31::from(1),
            M31::from(2),
            M31::from(3),
            M31::from(4),
            M31::from(5),
        ];

        let batched = batch_values(&values, 2);

        assert_eq!(batched.len(), 3);
        assert_eq!(batched[0], vec![M31::from(1), M31::from(2)]);
        assert_eq!(batched[1], vec![M31::from(3), M31::from(4)]);
        assert_eq!(batched[2], vec![M31::from(5), M31::zero()]);

        let unbatched = unbatch_values(&batched);

        assert_eq!(unbatched.len(), 6);
        assert_eq!(unbatched[0], M31::from(1));
        assert_eq!(unbatched[1], M31::from(2));
        assert_eq!(unbatched[2], M31::from(3));
        assert_eq!(unbatched[3], M31::from(4));
        assert_eq!(unbatched[4], M31::from(5));
        assert_eq!(unbatched[5], M31::zero());
    }
}
