// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::sync::{Arc, RwLock};
use std::convert::TryInto;
use std::num::TryFromIntError;

use failure::Fail;

use crate::merkle_storage::{MerkleStorage, MerkleError, ContextKey, ContextValue, MerkleStorageStats, EntryHash, StringTree};
use crypto::hash::{BlockHash, ContextHash, HashType};
use crate::{BlockStorage, BlockStorageReader, StorageError};

/// Abstraction on context manipulation
pub trait ContextApi {
    // set key-value
    fn set(&mut self, context_hash: &Option<ContextHash>, key: &ContextKey, value: &ContextValue) -> Result<(), ContextError>;
    // checkout context for hash
    fn checkout(&self, context_hash: &ContextHash) -> Result<(), ContextError>;
    // commit current context diff to storage
    // if parent_context_hash is empty, it means that it's a commit_genesis and we don't assign context_hash to header
    fn commit(&mut self, block_hash: &BlockHash, parent_context_hash: &Option<ContextHash>,
              new_context_hash: &ContextHash, author: String, message: String,
              date: i64) -> Result<(), ContextError>;
    fn delete_to_diff(&self, context_hash: &Option<ContextHash>, key_prefix_to_delete: &ContextKey) -> Result<(), ContextError>;
    fn remove_recursively_to_diff(&self, context_hash: &Option<ContextHash>, key_prefix_to_remove: &ContextKey) -> Result<(), ContextError>;
    // copies subtree under 'from_key' to new subtree under 'to_key'
    fn copy_to_diff(&self, context_hash: &Option<ContextHash>, from_key: &ContextKey, to_key: &ContextKey) -> Result<(), ContextError>;
    // get value for key
    fn get_key(&self, key: &ContextKey) -> Result<ContextValue, ContextError>;
    // get values by key prefix
    fn get_by_key_prefix(&self, prefix: &ContextKey) -> Result<Option<Vec<(ContextKey, ContextValue)>>, ContextError>;
    // get value for key from a point in history indicated by context hash
    fn get_key_from_history(&self, context_hash: &ContextHash, key: &ContextKey) -> Result<Option<ContextValue>, ContextError>;
    // get a list of all key-values under a certain key prefix
    fn get_key_values_by_prefix(&self, context_hash: &ContextHash, prefix: &ContextKey) -> Result<Option<Vec<(ContextKey, ContextValue)>>, MerkleError>;
    // get entire context tree in string form for JSON RPC
    fn get_context_tree_by_prefix(&self, context_hash: &ContextHash, prefix: &Option<&str>) -> Result<StringTree, MerkleError>;
    // convert level number to hash (uses block_storage get_by_block_Level)
    fn level_to_hash(&self, level: i32) -> Result<ContextHash, ContextError>;
    // get currently checked out hash
    fn get_last_commit_hash(&self) -> Option<Vec<u8>>;
    // get stats from merkle storage
    fn get_merkle_stats(&self) -> Result<MerkleStorageStats, ContextError>;
}

impl ContextApi for TezedgeContext {
    fn set(&mut self, _context_hash: &Option<ContextHash>, key: &ContextKey, value: &ContextValue) -> Result<(), ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        merkle.set(key, value)?;

        Ok(())
    }

    fn checkout(&self, context_hash: &ContextHash) -> Result<(), ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        let context_hash_arr: EntryHash = context_hash.as_slice().try_into().expect("EntryHash conversion error");
        merkle.checkout(&context_hash_arr)?;

        Ok(())
    }

    fn commit(&mut self, block_hash: &BlockHash, parent_context_hash: &Option<ContextHash>,
              new_context_hash: &ContextHash, author: String, message: String,
              date: i64) -> Result<(), ContextError> {

        let mut merkle = self.merkle.write().expect("lock poisoning");

        let date: u64 = date.try_into()?;
        let commit_hash = merkle.commit(date, author, message)?;
        let new_hash_arr: EntryHash = new_context_hash.as_slice().try_into().expect("EntryHash conversion error");
        assert_eq!(&commit_hash, &new_hash_arr);

        // associate block and context_hash
        if let Err(e) = self.block_storage.assign_to_context(block_hash, new_context_hash) {
            match e {
                StorageError::MissingKey => {
                    if parent_context_hash.is_some() {
                        return Err(
                            ContextError::ContextHashAssignError {
                                block_hash: HashType::BlockHash.bytes_to_string(block_hash),
                                context_hash: HashType::ContextHash.bytes_to_string(new_context_hash),
                                error: e,
                            }
                        );
                    } else {
                        // if parent_context_hash is empty, means it is commit_genesis, and block is not already stored, thats ok
                        ()
                    }
                }
                _ => return Err(
                    ContextError::ContextHashAssignError {
                        block_hash: HashType::BlockHash.bytes_to_string(block_hash),
                        context_hash: HashType::ContextHash.bytes_to_string(new_context_hash),
                        error: e,
                    }
                )
            };
        }

        Ok(())
    }

    fn delete_to_diff(&self, _context_hash: &Option<ContextHash>, key_prefix_to_delete: &ContextKey) -> Result<(), ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        merkle.delete(key_prefix_to_delete)?;
        Ok(())
    }

    fn remove_recursively_to_diff(&self, _context_hash: &Option<ContextHash>, key_prefix_to_remove: &ContextKey) -> Result<(), ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        merkle.delete(key_prefix_to_remove)?;
        Ok(())
    }

    fn copy_to_diff(&self, _context_hash: &Option<ContextHash>, from_key: &ContextKey, to_key: &ContextKey) -> Result<(), ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        merkle.copy(from_key, to_key)?;
        Ok(())
    }

    fn get_key(&self, key: &ContextKey) -> Result<ContextValue, ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        let val = merkle.get(key)?;
        Ok(val)
    }

    fn get_by_key_prefix(&self, prefix: &ContextKey) -> Result<Option<Vec<(ContextKey, ContextValue)>>, ContextError> {
        let mut merkle = self.merkle.write().expect("lock poisoning");
        let val = merkle.get_by_prefix(prefix)?;
        Ok(val)
    }

    fn get_key_from_history(&self, context_hash: &ContextHash, key: &ContextKey) -> Result<Option<ContextValue>, ContextError> {
        let merkle = self.merkle.read().expect("lock poisoning");
        // clients may pass in a prefix with elements containing slashes (expecting us to split)
        // we need to join with '/' and split again
        let key = to_key(key).split('/').map(|s| s.to_string()).collect();

        let context_hash_arr: EntryHash = context_hash.as_slice().try_into().expect("EntryHash conversion error");
        match merkle.get_history(&context_hash_arr, &key) {
            Err(MerkleError::ValueNotFound{key: _}) => Ok(None),
            Err(MerkleError::EntryNotFound{hash: _}) =>  {
                Err(ContextError::UnknownContextHashError { context_hash: HashType::ContextHash.bytes_to_string(context_hash) })
            },
            Err(err) => {
                Err(ContextError::MerkleStorageError { error: err })
            },
            Ok(val) => Ok(Some(val))
        }
    }

    fn get_key_values_by_prefix(&self, context_hash: &ContextHash, prefix: &ContextKey) -> Result<Option<Vec<(ContextKey, ContextValue)>>, MerkleError> {
        let merkle = self.merkle.read().expect("lock poisoning");
        // clients may pass in a prefix with elements containing slashes (expecting us to split)
        // we need to join with '/' and split again
        let prefix = to_key(prefix).split('/').map(|s| s.to_string()).collect();
        let context_hash_arr: EntryHash = context_hash.as_slice().try_into().expect("EntryHash conversion error");
        merkle.get_key_values_by_prefix(&context_hash_arr, &prefix)
    }

    fn get_context_tree_by_prefix(&self, context_hash: &ContextHash, prefix: &Option<&str>) -> Result<StringTree, MerkleError> {
        let merkle = self.merkle.read().expect("lock poisoning");
        // clients may pass in a prefix with elements containing slashes (expecting us to split)
        // we need to join with '/' and split again
        let prefix: ContextKey = match prefix {
            Some(prefix) => prefix.split('/').map(|s| s.to_string()).collect(),
            None => vec![],
        };
        let context_hash_arr: EntryHash = context_hash.as_slice().try_into().expect("EntryHash conversion error");
        merkle.get_context_tree_by_prefix(&context_hash_arr, &prefix)
    }

    fn level_to_hash(&self, level: i32) -> Result<ContextHash, ContextError> {
        match self.block_storage.get_by_block_level(level) {
            Ok(Some(hash)) => {
                Ok(hash.header.context().to_vec())
            },
            _ => Err(ContextError::UnknownLevelError{level: level.to_string()})
        }
    }

    fn get_last_commit_hash(&self) -> Option<Vec<u8>> {
        let merkle = self.merkle.read().expect("lock poisoning");
        merkle.get_last_commit_hash().map(|x| x.to_vec())
    }

    fn get_merkle_stats(&self) -> Result<MerkleStorageStats, ContextError> {
        let merkle = self.merkle.read().expect("lock poisoning");
        let stats = merkle.get_merkle_stats()?;

        Ok(stats)
    }
}

fn to_key(key: &ContextKey) -> String {
    key.join("/")
}

// context implementation using merkle-tree-like storage
pub struct TezedgeContext {
    block_storage: BlockStorage,
    merkle: Arc<RwLock<MerkleStorage>>,
}

impl TezedgeContext {
    pub fn new(block_storage: BlockStorage, merkle: Arc<RwLock<MerkleStorage>>) -> Self {
        TezedgeContext { block_storage, merkle }
    }
}

/// Possible errors for context
#[derive(Debug, Fail)]
pub enum ContextError {
    #[fail(display = "Failed to assign context_hash: {:?} to block_hash: {}, error: {}", context_hash, block_hash, error)]
    ContextHashAssignError {
        context_hash: String,
        block_hash: String,
        error: StorageError,
    },
    #[fail(display = "Unknown context_hash: {:?}", context_hash)]
    UnknownContextHashError {
        context_hash: String,
    },
    #[fail(display = "Unknown level: {}", level)]
    UnknownLevelError {
        level: String,
    },
    #[fail(display = "Failed operation on Merkle storage: {}", error)]
    MerkleStorageError {
        error: MerkleError,
    },
    #[fail(display = "Invalid commit date: {}", error)]
    InvalidCommitDate {
        error: TryFromIntError,
    },
}

impl From<MerkleError> for ContextError {
    fn from(error: MerkleError) -> Self {
        ContextError::MerkleStorageError { error }
    }
}
impl From<TryFromIntError> for ContextError {
    fn from(error: TryFromIntError) -> Self {
        ContextError::InvalidCommitDate { error }
    }
}
