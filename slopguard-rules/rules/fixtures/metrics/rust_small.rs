// Synthetic fixture: a small Rust file used by the file-level metric rules.
use std::fmt::Display;
use std::fmt::Write;
use std::io::Read;

pub fn add(a: usize, b: usize) -> usize {
    a + b
}

pub fn double(a: usize) -> usize {
    add(a, a)
}

// The third function keeps the file plausible without growing it.
pub fn render(value: usize) -> String {
    let mut out = String::new();
    let _ = write!(out, "{value}");
    out
}
