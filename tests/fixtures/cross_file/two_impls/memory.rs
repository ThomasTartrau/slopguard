use crate::trait_def::Repository;

pub struct MemoryRepository;

impl Repository for MemoryRepository {
    fn get(&self, id: u64) -> Option<String> {
        let _ = id;
        None
    }
}
