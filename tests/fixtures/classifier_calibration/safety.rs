//! Calibration fixture: unsafe blocks with SAFETY comments of varying quality.
//! Each unsafe block is spread far enough from the next that the context radius
//! (25 vs 50) changes how much surrounding code the classifier sees. Labels for
//! each block live in labels.json, keyed by the 1-based line of the unsafe block.

use std::ptr;
use std::slice;

fn read_first(values: &[u32]) -> u32 {
    let base = values.as_ptr();
    let count = values.len();
    let _ = count;
    // SAFETY: this is safe
    let first = unsafe { ptr::read(base) };
    first
}

fn double_all(values: &mut [u32]) {
    for value in values.iter_mut() {
        *value = value.wrapping_mul(2);
    }
}

fn describe(values: &[u32]) -> String {
    format!("len={}", values.len())
}

fn last_unchecked(values: &[u32]) -> u32 {
    let len = values.len();
    let base = values.as_ptr();
    // SAFETY: trust me, we already checked everything above
    let last = unsafe { ptr::read(base.add(len - 1)) };
    last
}

fn sum(values: &[u32]) -> u64 {
    values.iter().map(|v| *v as u64).sum()
}

fn is_sorted(values: &[u32]) -> bool {
    values.windows(2).all(|w| w[0] <= w[1])
}

fn head(values: &[u32], n: usize) -> &[u32] {
    let len = values.len().min(n);
    let base = values.as_ptr();
    // SAFETY: len is clamped to values.len() with min(n), so base is valid for
    // len contiguous u32 reads and the slice never runs past the allocation.
    unsafe { slice::from_raw_parts(base, len) }
}

fn tail(values: &[u32], n: usize) -> Vec<u32> {
    let start = values.len().saturating_sub(n);
    values[start..].to_vec()
}

fn average(values: &[u32]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    Some(sum(values) / values.len() as u64)
}

fn get_unchecked_at(values: &[u32], i: usize) -> u32 {
    let base = values.as_ptr();
    // SAFETY: i < values.len() is guaranteed by the caller's bounds check on the
    // preceding line, so base.add(i) stays inside the same allocation.
    unsafe { ptr::read(base.add(i)) }
}
