pub trait Repository {
    fn get(&self, id: u64) -> Option<String>;
}
