// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::cmp;
use std::cmp::Ordering;
use std::cell::{RefCell, RefMut};

use rand::rngs::mock::StepRng;
use rand::{Rng, RngCore};
use slog::Logger;

use crypto::hash::{BlockHash, ChainId};
use storage::{BlockHeaderWithHash, BlockMetaStorage, BlockStorage, BlockStorageReader, ChainMetaStorage, IteratorMode, StorageError};
use storage::persistent::PersistentStorage;
use tezos_messages::Head;
use tezos_messages::p2p::encoding::block_header::Level;
use tezos_messages::p2p::encoding::current_branch::HISTORY_MAX_SIZE;

use crate::collections::{BlockData, UniqueBlockData};
use crate::shell_channel::BlockApplied;

struct MaybeRng<'a>(Option<RefMut<'a, StepRng>>);

impl<'a> RngCore for MaybeRng<'a> {
    fn next_u32(&mut self) -> u32 {
        match self.0.as_deref_mut() {
            Some(r) => r.next_u32(),
            None => rand::thread_rng().next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self.0.as_deref_mut() {
            Some(r) => r.next_u64(),
            None => rand::thread_rng().next_u64(),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self.0.as_deref_mut() {
            Some(r) => r.fill_bytes(dest),
            None => rand::thread_rng().fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self.0.as_deref_mut() {
            Some(r) => r.try_fill_bytes(dest),
            None => rand::thread_rng().try_fill_bytes(dest),
        }
    }
}

/// Holds state of all known blocks
pub struct BlockchainState {
    /// persistent block storage
    block_storage: BlockStorage,
    ///persistent block metadata storage
    block_meta_storage: BlockMetaStorage,
    ///persistent chain metadata storage
    chain_meta_storage: ChainMetaStorage,
    /// Current missing blocks.
    /// This represents a set of missing block we will try to retrieve in the future.
    /// Before we try to fetch missing block it is removed from this queue.
    /// Block is then sent to [`chain_manager`](crate::chain_manager::ChainManager) actor whose responsibility is to
    /// retrieve the block data. If the block data cannot be fetched it's the responsibility
    /// of the [`chain_manager`](crate::chain_manager::ChainManager) to return the block to this queue.
    missing_blocks: UniqueBlockData<MissingBlock>,
    chain_id: ChainId,
    /// predictable rng for testing
    rng: Option<RefCell<StepRng>>,
}

impl BlockchainState {
    pub fn new(persistent_storage: &PersistentStorage, chain_id: &ChainId) -> Self {
        BlockchainState {
            block_storage: BlockStorage::new(persistent_storage),
            block_meta_storage: BlockMetaStorage::new(persistent_storage),
            chain_meta_storage: ChainMetaStorage::new(persistent_storage),
            missing_blocks: UniqueBlockData::new(),
            chain_id: chain_id.clone(),
            rng: Some(RefCell::new(StepRng::new(0x123456789abcdef0, 0xabcdef0123456789))),
        }
    }

    /// Resolve if new applied block can be set as new current head.
    /// Original algorithm is in [chain_validator][on_request], where just fitness is checked.
    /// Returns:
    /// - None, if head was not updated
    /// - Some(head), if head was updated
    pub fn try_set_new_current_head(&self, block: &BlockApplied) -> Result<Option<Head>, StorageError> {

        let head = Head::new(block.header().hash.clone(), block.header().header.level());

        // set head to db
        self.chain_meta_storage.set_current_head(&self.chain_id, head.clone())?;

        Ok(Some(head))
    }

    pub fn process_block_header(&mut self, block_header: &BlockHeaderWithHash, log: &Logger) -> Result<(), StorageError> {
        // check if we already have seen predecessor
        self.push_missing_block(
            MissingBlock::with_level_guess(
                block_header.header.predecessor().clone(),
                block_header.header.level() - 1,
            )
        )?;

        // store block
        self.block_storage.put_block_header(block_header)?;
        // update meta
        self.block_meta_storage.put_block_header(block_header, &self.chain_id, &log)?;

        Ok(())
    }

    #[inline]
    pub fn drain_missing_blocks(&mut self, n: usize, level_max: i32) -> Vec<MissingBlock> {
        (0..cmp::min(self.missing_blocks.len(), n))
            .filter_map(|_| {
                if self.missing_blocks.peek().filter(|block| block.fits_to_max(level_max)).is_some() {
                    self.missing_blocks.pop()
                } else {
                    None
                }
            })
            .collect()
    }

    #[inline]
    pub fn push_missing_block(&mut self, missing_block: MissingBlock) -> Result<(), StorageError> {
        if !self.block_storage.contains(&missing_block.block_hash)? {
            self.missing_blocks.push(missing_block);
        }
        Ok(())
    }

    #[inline]
    pub fn push_missing_history(&mut self, history: Vec<BlockHash>, level: Level) -> Result<(), StorageError> {
        let history_max_parts = if history.len() < usize::from(HISTORY_MAX_SIZE) {
            history.len() as u8
        } else {
            HISTORY_MAX_SIZE
        };

        history.iter().enumerate()
            .map(|(idx, history_block_hash)| {
                let rng = MaybeRng(self.rng.as_ref().map(RefCell::borrow_mut));
                let level = Self::guess_level(rng, level, history_max_parts, idx);
                self.push_missing_block(
                    MissingBlock::with_level_guess(
                        history_block_hash.clone(),
                        level,
                    )
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    #[inline]
    pub fn has_missing_blocks(&self) -> bool {
        !self.missing_blocks.is_empty()
    }

    #[inline]
    pub fn missing_blocks_count(&self) -> usize {
        self.missing_blocks.len()
    }

    pub fn hydrate(&mut self) -> Result<(), StorageError> {
        for (key, value) in self.block_meta_storage.iter(IteratorMode::Start)? {
            let (block_hash, meta) = (key?, value?);
            if meta.predecessor().is_none() && (meta.chain_id() == &self.chain_id) {
                self.missing_blocks.push(
                    MissingBlock::with_level(
                        block_hash,
                        meta.level(),
                    )
                );
            }
        }

        Ok(())
    }

    #[inline]
    pub fn get_chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    pub fn get_history(&self) -> Result<Vec<BlockHash>, StorageError> {
        let history_max = 20;
        let mut history = Vec::with_capacity(history_max);
        let mut rng = rand::thread_rng();
        for (key, value) in self.block_meta_storage.iter(IteratorMode::Start)? {
            let pivot = (1 + rng.gen::<u8>() % 24) as i32;
            let (block_hash, meta) = (key?, value?);
            if meta.is_applied() && (meta.level() != 0) && (meta.level() % pivot == 0) && (meta.chain_id() == &self.chain_id) {
                history.push(block_hash);
                if history.len() >= history_max {
                    break;
                }
            }
        }
        Ok(history)
    }

    fn guess_level<R>(mut rng: R, level: Level, parts: u8, index: usize) -> i32
    where
        R: rand::Rng,
    {
        // e.g. we have: level 100 a 5 record in history, so split is 20, never <= 0
        let split = level / i32::from(parts);
        // corner case for 1 level;
        let split = cmp::max(1, split);

        // we try to guess level, because in history there is no level
        if index == 0 {
            // first block in history is always genesis
            0
        } else {
            // e.g. next block: idx * split, e.g. for index in history: 1 and split, we guess level is in range (0 * 20 - 1 * 20) -> (0, 20)
            let start_level = ((index as i32 - 1) * split) + 1;
            let end_level = (index as i32) * split;

            // corner case for 1 level
            let start_level = cmp::min(start_level, level);
            let end_level = cmp::min(end_level, level);

            if start_level == end_level {
                start_level
            } else {
                rng.gen_range(start_level, end_level)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct MissingBlock {
    pub block_hash: BlockHash,
    // if level is known, we use level
    level: Option<i32>,
    // if level is unknow, we 'guess' level
    level_guess: Option<i32>,
}

impl BlockData for MissingBlock {
    #[inline]
    fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }
}

impl MissingBlock {
    pub fn with_level(block_hash: BlockHash, level: i32) -> Self {
        MissingBlock {
            block_hash,
            level: Some(level),
            level_guess: None,
        }
    }

    pub fn with_level_guess(block_hash: BlockHash, level_guess: i32) -> Self {
        MissingBlock {
            block_hash,
            level: None,
            level_guess: Some(level_guess),
        }
    }

    fn fits_to_max(&self, level_max: i32) -> bool {
        if let Some(level) = self.level {
            return level <= level_max;
        }

        if let Some(level_guess) = self.level_guess {
            return level_guess <= level_max;
        }

        // if both are None
        true
    }
}

impl PartialEq for MissingBlock {
    fn eq(&self, other: &Self) -> bool {
        self.block_hash == other.block_hash
    }
}

impl Eq for MissingBlock {}

impl PartialOrd for MissingBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MissingBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_potential_level = match self.level {
            Some(level) => level,
            None => match self.level_guess {
                Some(level) => level,
                None => 0
            }
        };
        let other_potential_level = match other.level {
            Some(level) => level,
            None => match other.level_guess {
                Some(level) => level,
                None => 0
            }
        };

        // reverse, because we want lower level at begining
        self_potential_level.cmp(&other_potential_level).reverse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_blocks_has_correct_ordering() {
        let mut heap = UniqueBlockData::new();

        // simulate header and predecesor
        heap.push(MissingBlock::with_level(vec![0, 0, 0, 1], 10));
        heap.push(MissingBlock::with_level(vec![0, 0, 0, 2], 9));

        // simulate history
        heap.push(MissingBlock::with_level_guess(vec![0, 0, 0, 3], 4));
        heap.push(MissingBlock::with_level_guess(vec![0, 0, 0, 7], 0));
        heap.push(MissingBlock::with_level_guess(vec![0, 0, 0, 5], 2));
        heap.push(MissingBlock::with_level_guess(vec![0, 0, 0, 6], 1));
        heap.push(MissingBlock::with_level_guess(vec![0, 0, 0, 4], 3));

        // pop all from heap
        let ordered_hashes = (0..heap.len())
            .map(|_| heap.pop().unwrap())
            .map(|i| i.block_hash)
            .collect::<Vec<BlockHash>>();

        // from level: 0, 1, 2, 3, 4, 9, 10
        let expected_order = vec![
            vec![0, 0, 0, 7],
            vec![0, 0, 0, 6],
            vec![0, 0, 0, 5],
            vec![0, 0, 0, 4],
            vec![0, 0, 0, 3],
            vec![0, 0, 0, 2],
            vec![0, 0, 0, 1],
        ];

        assert_eq!(expected_order, ordered_hashes)
    }

    #[test]
    fn test_guess_level() {
        let mut rng = rand::thread_rng();

        // for block 0 in history (always 0)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 0);
            assert_eq!(level, 0);
        }

        // for block 1 in history [1, 20)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 1);
            assert!(level >= 1 && level < 20);
        }

        // for block 2 in history [20, 40)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 2);
            assert!(level >= 20 && level < 40);
        }

        // for block 3 in history [40, 60)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 3);
            assert!(level >= 40 && level < 60);
        }

        // for block 4 in history [60, 80)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 4);
            assert!(level >= 60 && level < 80);
        }

        // for block 5 in history [80, 100)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 100, 5, 5);
            assert!(level >= 80 && level < 100);
        }

        // for block 0 in history [0, 1)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 1, 1, 0);
            assert!(level >= 0 && level < 1);
        }

        // corner case (for level 1 if there are two elements)
        // for block 0 in history [0, 1)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 1, 2, 0);
            assert!(level >= 0 && level < 1);
        }

        // corner case (for level 1 if there are two elements)
        // for block 1 in history [1, 2)
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 1, 2, 1);
            assert!(level >= 1 && level < 2);
        }

        // corner cases
        for _ in 0..100 {
            let level = BlockchainState::guess_level(&mut rng, 1, 3, 0);
            assert!(level >= 0 && level < 1);
            let level = BlockchainState::guess_level(&mut rng, 1, 3, 1);
            assert!(level >= 1 && level < 2);
            let level = BlockchainState::guess_level(&mut rng, 1, 3, 2);
            assert!(level >= 1 && level < 2);
        }
    }
}