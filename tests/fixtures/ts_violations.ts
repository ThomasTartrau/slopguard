// Fixture: one violation per TypeScript rule that fires in a real scan.
// no-useeffect-derived-state is excluded: its inline tests fail.

// --- correctness/no-any-typescript (error) ---
function parse(data: any): string { return data; }

// --- correctness/no-async-foreach (error) ---
items.forEach(async (item) => { await process(item); });

// --- correctness/no-replace-single (warning) ---
const slug = title.replace(' ', '-');

// --- correctness/no-sort-without-comparator (error) ---
const sorted = numbers.sort();
