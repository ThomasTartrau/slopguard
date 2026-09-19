use crate::trait_def::Repository;

pub struct PostgresRepository;

impl Repository for PostgresRepository {
    fn get(&self, id: u64) -> Option<String> {
        let _ = id;
        None
    }
}
