//! Edit arithmetic for `--fix`: the raw text replacements, how a pass picks
//! the groups it can apply together, and how protected ranges follow the
//! buffer as it changes.

use crate::rule::RuleId;

/// A single text replacement, decoupled from ast-grep's borrowed `Edit` so it
/// outlives the parsed tree.
pub(super) struct RawEdit {
    pub(super) position: usize,
    pub(super) deleted_length: usize,
    pub(super) inserted: Vec<u8>,
}

/// A match `--fix` must leave alone (inline disable or baseline), as a byte
/// range of the current buffer for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Protected {
    pub(super) rule_id: RuleId,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Apply non-overlapping edits (sorted ascending) to `source`, right to left so
/// earlier positions stay valid. Returns the new content and the number of
/// edits actually spliced: an out-of-bounds edit is skipped and not counted,
/// and an invalid UTF-8 result yields the original content with 0 applied.
pub(super) fn apply_edits(source: &str, edits: &[RawEdit]) -> (String, usize) {
    let mut bytes = source.as_bytes().to_vec();
    let mut applied = 0;
    for edit in edits.iter().rev() {
        let end = edit.position + edit.deleted_length;
        if end > bytes.len() {
            continue;
        }
        bytes.splice(edit.position..end, edit.inserted.iter().copied());
        applied += 1;
    }
    match String::from_utf8(bytes) {
        Ok(fixed) => (fixed, applied),
        Err(_) => (source.to_string(), 0),
    }
}

/// Whether two edits cannot both apply in one pass: their ranges overlap, or
/// they start at the same position (two inserts there would land in an
/// arbitrary order).
fn conflicts(a: &RawEdit, b: &RawEdit) -> bool {
    a.position == b.position
        || (a.position < b.position + b.deleted_length
            && b.position < a.position + a.deleted_length)
}

/// Greedily keep, in source order, the edit groups none of whose edits
/// conflicts with a previously kept one, and return their edits sorted by
/// position. A dropped group (a nested or duplicate match, or two fixes of one
/// enum) is left for the next fix-point iteration. Also returns how many
/// groups were kept.
pub(super) fn select_non_overlapping(
    mut groups: Vec<Vec<RawEdit>>,
    len: usize,
) -> (Vec<RawEdit>, usize) {
    groups.retain(|g| !g.is_empty() && g.iter().all(|e| e.position + e.deleted_length <= len));
    groups.sort_by_key(|g| g.iter().map(|e| e.position).min());
    let mut kept: Vec<RawEdit> = Vec::new();
    let mut count = 0;
    for group in groups {
        if group.iter().all(|e| !kept.iter().any(|k| conflicts(e, k))) {
            kept.extend(group);
            count += 1;
        }
    }
    kept.sort_by_key(|e| e.position);
    (kept, count)
}

/// Move the protected ranges through one pass of applied edits (sorted
/// ascending, non-overlapping, positions in the pre-pass buffer). A range after
/// an edit shifts by the length delta; a range an edit touches is widened to
/// cover the replacement, so it keeps protecting the text it held.
pub(super) fn shift_protected(protected: &mut [Protected], edits: &[RawEdit]) {
    // Right to left: an edit never moves the positions before it, so each
    // edit's coordinates stay valid while the later ones are folded in.
    for edit in edits.iter().rev() {
        let edit_end = edit.position + edit.deleted_length;
        let inserted = edit.inserted.len();
        for range in protected.iter_mut() {
            if edit_end <= range.start {
                // `range.start >= edit_end >= deleted_length`: no underflow.
                range.start = range.start - edit.deleted_length + inserted;
                range.end = range.end - edit.deleted_length + inserted;
            } else if edit.position < range.end {
                // `max(end, edit_end) >= edit_end >= deleted_length`.
                range.end = range.end.max(edit_end) - edit.deleted_length + inserted;
                range.start = range.start.min(edit.position);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(position: usize) -> RawEdit {
        RawEdit {
            position,
            deleted_length: 0,
            inserted: b"x".to_vec(),
        }
    }

    #[test]
    fn two_inserts_at_one_position_go_to_separate_passes() {
        let (kept, groups) = select_non_overlapping(vec![vec![insert(3)], vec![insert(3)]], 10);
        assert_eq!((kept.len(), groups), (1, 1));
    }

    #[test]
    fn a_group_is_kept_whole_or_dropped_whole() {
        let replace = |position, deleted_length| RawEdit {
            position,
            deleted_length,
            inserted: Vec::new(),
        };
        // The second group's tail overlaps the first group: none of it applies.
        let groups = vec![
            vec![replace(0, 2), replace(8, 2)],
            vec![replace(4, 1), replace(9, 1)],
            vec![insert(6)],
        ];
        let (kept, count) = select_non_overlapping(groups, 10);
        let positions: Vec<_> = kept.iter().map(|e| e.position).collect();
        assert_eq!((positions, count), (vec![0, 6, 8], 2));
    }
}
