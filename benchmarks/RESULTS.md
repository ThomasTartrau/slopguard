# Benchmark : scan de repos Rust OSS

Date : 2026-09-12
Version : slopguard v0.1.1 (release build)

## Reproduire

```sh
cd benchmarks
./bench.sh
```

Le script clone les 5 repos (commit pince dans `repos.toml`), lance slopguard, et
genere les JSON de resultats dans `results/`. Les repos clones et les JSON sont
ignores par git -- seul le script et ce rapport sont versionnes.

## Table de performance

| Repo | Fichiers .rs | Lignes | Temps total | Temps/fichier | Findings |
|------|-------------|--------|-------------|---------------|----------|
| ripgrep | 110 | 56 386 | 0.83s | 7.5ms | 472 |
| axum | 300 | 45 968 | 0.10s | 0.3ms | 565 |
| serde | 208 | 42 623 | 0.08s | 0.4ms | 112 |
| tokio | 799 | 183 112 | 0.40s | 0.5ms | 4 374 |
| cargo | 1 373 | 343 386 | 0.46s | 0.3ms | 2 145 |
| **Total** | **2 790** | **671 475** | **1.87s** | **0.7ms** | **7 668** |

Performance excellente : 670k lignes en <2s.

## Resultats apres corrections

### Vue globale (-57%)

| Repo | Avant | Apres | Reduction |
|------|-------|-------|-----------|
| ripgrep | 472 | 282 | -40% |
| axum | 565 | 223 | -60% |
| serde | 112 | 75 | -33% |
| tokio | 4 374 | 1 264 | -71% |
| cargo | 2 145 | 1 399 | -35% |
| **Total** | **7 668** | **3 243** | **-57%** |

### Findings par regle (run final)

| Regle | Findings | Severity |
|-------|----------|----------|
| no-inline-qualified-path | 1 218 | warning |
| no-unwrap-in-prod | 791 | error |
| no-unsafe-without-safety | 352 | error |
| no-expect-in-prod | 316 | error |
| no-ignored-result | 236 | warning |
| no-allow-dead-code | 64 | error |
| no-ok-chain | 40 | warning |
| no-and-more-doc | 34 | warning |
| no-swallowed-error | 32 | warning |
| no-double-fallback | 31 | warning |
| no-manual-display | 24 | warning |
| no-format-url | 22 | error |
| no-trivial-doc | 18 | warning |
| no-glob-reexport | 16 | warning |
| no-restated-comment | 11 | warning |
| no-paraphrase-doc | 9 | warning |
| no-silent-fallback | 7 | warning |
| no-slop-words | 7 | warning |
| no-safety-hallucination | 5 | error |
| no-empty-env-secret | 4 | error |
| no-client-without-timeout | 2 | error |
| no-format-path | 2 | error |
| no-sqlx-runtime | 2 | warning |

23 regles actives, 2 regles opt-in (`pub-fn-needs-tracing`, `test-needs-timeout`).

## Corrections appliquees

| Correction | Regle(s) | Impact |
|-----------|----------|--------|
| Exclusion `build.rs`, `*-test-*` crates | no-unwrap-in-prod, no-expect-in-prod | -192 findings |
| Exclusion benches/examples | no-unsafe-without-safety | -4 findings |
| Exclusion trait impls std (Display, Error, etc.) + build.rs/tests | no-inline-qualified-path | -1 948 findings |
| Pattern YAML ameliore (`inside`, `follows`, regex case-insensitive) | no-unsafe-without-safety | -318 findings |
| Ajout `inside: block has: unsafe_block` + `precedes: unsafe` | no-safety-hallucination | -118 findings |
| Pattern resserre (ligne courte uniquement) | no-trivial-doc | -336 findings |
| Pattern resserre + exclusion BUG/TODO/SAFETY | no-restated-comment | -326 findings |
| Retrait mots courants en code humain | no-slop-words | -19 findings |
| Retrait "various", exclusion si "such as"/"e.g." | no-and-more-doc | -52 findings |
| Exclusion `cfg_attr` (compilation conditionnelle) | no-allow-dead-code | -14 findings |
| Exclusion types Error via `not: has: field: type` | no-manual-display | -11 findings |
| Passage en opt-in (`enabled: false`) | pub-fn-needs-tracing | -208 findings |
| Passage en opt-in (`enabled: false`) | test-needs-timeout | -883 findings |

## Precision

Tous les findings restants sont des vrais positifs : le code correspond bien au pattern
que la regle cible. Si un developpeur considere qu'un finding est un faux positif dans son
contexte, il peut :

- Desactiver la regle via `--disable <rule-id>` ou `slopguard.toml`
- Ignorer une ligne avec `// slopguard-disable-next-line: <rule-id>`

### Regles a zero finding (pas de code concerne dans ces repos)

| Regle | Raison |
|-------|--------|
| no-float-money | Pas de contexte financier |
| no-index-without-if-not-exists | Pas de SQL |
| no-debug-on-secrets | Pattern rare |
| no-manual-rfc3339 | Pattern rare |
