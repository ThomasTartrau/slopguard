#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOS_DIR="$SCRIPT_DIR/.repos"
RESULTS_DIR="$SCRIPT_DIR/results"
SLOPGUARD="${SLOPGUARD_BIN:-cargo run --release --manifest-path "$SCRIPT_DIR/../Cargo.toml" --}"

mkdir -p "$REPOS_DIR" "$RESULTS_DIR"

repos=(ripgrep axum serde tokio cargo)
urls=(
  "https://github.com/BurntSushi/ripgrep.git"
  "https://github.com/tokio-rs/axum.git"
  "https://github.com/serde-rs/serde.git"
  "https://github.com/tokio-rs/tokio.git"
  "https://github.com/rust-lang/cargo.git"
)

# Parse optional --rev from repos.toml (falls back to HEAD)
get_rev() {
  local name="$1"
  if command -v python3 &>/dev/null; then
    python3 -c "
import tomllib, sys
with open('$SCRIPT_DIR/repos.toml', 'rb') as f:
    cfg = tomllib.load(f)
for r in cfg['repo']:
    if r['name'] == '$name':
        print(r.get('rev', 'HEAD'))
        sys.exit(0)
print('HEAD')
" 2>/dev/null || echo "HEAD"
  else
    echo "HEAD"
  fi
}

timestamp=$(date +%Y%m%d-%H%M%S)

echo "=== slopguard benchmark ==="
echo "timestamp: $timestamp"
echo ""

# Build slopguard first
echo "Building slopguard (release)..."
cargo build --release --manifest-path "$SCRIPT_DIR/../Cargo.toml" 2>&1 | tail -1
SLOPGUARD="$SCRIPT_DIR/../target/release/slopguard"
echo ""

total_findings=0
total_files=0

for i in "${!repos[@]}"; do
  name="${repos[$i]}"
  url="${urls[$i]}"
  rev=$(get_rev "$name")
  repo_dir="$REPOS_DIR/$name"

  echo "--- $name ---"

  # Clone or update
  if [ -d "$repo_dir" ]; then
    echo "  updating..."
    git -C "$repo_dir" fetch --quiet
  else
    echo "  cloning..."
    git clone --quiet "$url" "$repo_dir"
  fi

  # Checkout pinned rev
  if [ "$rev" != "HEAD" ]; then
    git -C "$repo_dir" checkout --quiet "$rev"
  fi

  actual_rev=$(git -C "$repo_dir" rev-parse --short HEAD)
  echo "  rev: $actual_rev"

  # Count .rs files
  rs_files=$(find "$repo_dir" -name '*.rs' -not -path '*/target/*' | wc -l | tr -d ' ')
  total_files=$((total_files + rs_files))
  echo "  files: $rs_files .rs"

  # Scan
  out="$RESULTS_DIR/${name}_${timestamp}.json"
  start=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
  $SLOPGUARD scan --format json "$repo_dir" > "$out" 2>/dev/null || true
  end=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")

  elapsed_ms=$(( (end - start) / 1000000 ))
  findings=$(python3 -c "import json; print(len(json.load(open('$out'))['findings']))")
  total_findings=$((total_findings + findings))

  echo "  findings: $findings"
  echo "  time: ${elapsed_ms}ms"
  echo ""
done

echo "=== summary ==="
echo "repos: ${#repos[@]}"
echo "total .rs files: $total_files"
echo "total findings: $total_findings"
echo "results in: $RESULTS_DIR/*_${timestamp}.json"

# Generate per-rule breakdown
echo ""
echo "=== per-rule breakdown ==="
python3 -c "
import json, os, collections

counts = collections.Counter()
for f in os.listdir('$RESULTS_DIR'):
    if not f.endswith('_${timestamp}.json'):
        continue
    data = json.load(open(os.path.join('$RESULTS_DIR', f)))
    for finding in data['findings']:
        counts[finding['rule_id']] += 1

for rule, count in counts.most_common():
    print(f'  {count:>5}  {rule}')
"
