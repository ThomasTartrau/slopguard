pub fn load() -> anyhow::Result<String> {
    do_thing().ok_or_else(|| anyhow::anyhow!("the configuration file could not be read"))
}

fn do_thing() -> Option<String> {
    None
}
