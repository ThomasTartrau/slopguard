pub mod json;
pub mod sarif;
pub mod stats;
pub mod text;

use std::io::{self, Write};

use serde::Serialize;

/// Pick the singular or plural label for a count.
pub(crate) fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}

/// Serialize `value` as pretty JSON followed by a trailing newline.
pub(crate) fn write_json_pretty<T: Serialize>(w: &mut impl Write, value: &T) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *w, value).map_err(io::Error::other)?;
    writeln!(w)
}
