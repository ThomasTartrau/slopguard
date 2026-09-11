use std::collections::HashMap;
use std::error::Error;

/// Panics if the connection pool is exhausted.
fn fetch_user(id: i64) -> Result<String, Box<dyn Error>> {
    let name = get_name(id)?;
    Ok(name)
}

fn process(items: &[i32]) -> i32 {
    items.iter().sum()
}

fn build_map() -> HashMap<String, i32> {
    let mut map = HashMap::new();
    map.insert("one".to_string(), 1);
    map
}
