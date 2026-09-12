# Benchmark : scan de repos Rust OSS

Date : 2026-09-12
Version : slopguard v0.1.1 (release build)

## Table de performance

### Run initial (avant corrections)

| Repo | Fichiers .rs | Lignes | Temps total | Temps/fichier | Findings |
|------|-------------|--------|-------------|---------------|----------|
| ripgrep | 110 | 56 386 | 0.83s | 7.5ms | 472 |
| axum | 300 | 45 968 | 0.10s | 0.3ms | 565 |
| serde | 208 | 42 623 | 0.08s | 0.4ms | 112 |
| tokio | 799 | 183 112 | 0.40s | 0.5ms | 4 374 |
| cargo | 1 373 | 343 386 | 0.46s | 0.3ms | 2 145 |
| **Total** | **2 790** | **671 475** | **1.87s** | **0.7ms** | **7 668** |

### Run apres corrections (-53%)

| Repo | Avant | Apres | Reduction |
|------|-------|-------|-----------|
| ripgrep | 472 | 286 | -39% |
| axum | 565 | 223 | -60% |
| serde | 112 | 76 | -32% |
| tokio | 4 374 | 1 597 | -63% |
| cargo | 2 145 | 1 405 | -34% |
| **Total** | **7 668** | **3 587** | **-53%** |

Performance excellente : 670k lignes en <2s.
ripgrep est plus lent car le premier scan (cold start tree-sitter).

## Table de precision par regle

Classification basee sur un echantillonnage manuel de 10-30 findings par regle.

- **VP** = Vrai Positif : le finding signale un probleme reel (meme si le code mature l'a fait volontairement)
- **FP** = Faux Positif : le finding se declenche sur du code correct/idiomatique, la regle est trop large

| Regle | Total | VP est. | FP est. | Taux FP | Severity | Action |
|-------|-------|---------|---------|---------|----------|--------|
| no-inline-qualified-path | 3 166 | ~300 | ~2 866 | **~90%** | warning | Affiner: exclure trait impls (fmt::Display, Error, etc.), build.rs, et tests |
| no-unwrap-in-prod | 944 | ~250 | ~694 | **~74%** | error | Affiner: exclure tests, benches, examples, build.rs, et `cfg(test)` |
| test-needs-timeout | 883 | ~100 | ~783 | **~89%** | warning | Affiner: exclure les tests unitaires sync, ne cibler que `#[tokio::test]` sans timeout |
| no-unsafe-without-safety | 670 | ~50 | ~620 | **~93%** | error | Affiner: beaucoup de blocs unsafe dans tokio ont un `// SAFETY:` mais la regle ne le detecte pas |
| no-expect-in-prod | 355 | ~80 | ~275 | **~77%** | error | Affiner: exclure tests/benches/examples/build.rs |
| no-trivial-doc | 354 | ~30 | ~324 | **~92%** | warning | Affiner: "This type is" suivi d'une explication utile n'est PAS trivial |
| no-restated-comment | 337 | ~50 | ~287 | **~85%** | warning | Affiner: le pattern est trop large, matche des commentaires explicatifs valides |
| no-ignored-result | 236 | ~180 | ~56 | **~24%** | warning | OK pour warning, mais exclure `let _ =` dans les benchmarks et tests teardown |
| pub-fn-needs-tracing | 208 | ~0 | ~208 | **~100%** | warning | Trop opinionnee: les libs OSS n'utilisent pas tracing sur chaque fn publique |
| no-safety-hallucination | 123 | ~10 | ~113 | **~92%** | error | Affiner: matche des vrais commentaires `// SAFETY:` qui sont corrects |
| no-and-more-doc | 86 | ~20 | ~66 | **~77%** | warning | Affiner: "and more" dans une vraie enumeration n'est pas du slop |
| no-allow-dead-code | 78 | ~30 | ~48 | **~62%** | error | Affiner: `#[cfg_attr(not(feature), allow(dead_code))]` est du code conditionnel valide |
| no-ok-chain | 40 | ~25 | ~15 | **~38%** | warning | Acceptable |
| no-manual-display | 35 | ~5 | ~30 | **~86%** | warning | Affiner: impl Display pour des types d'erreur custom est idiomatique |
| no-swallowed-error | 32 | ~15 | ~17 | **~53%** | warning | A la limite, revoir le pattern |
| no-double-fallback | 31 | ~10 | ~21 | **~68%** | warning | Affiner: `.ok().map()` est un pattern Rust idiomatique |
| no-slop-words | 26 | ~5 | ~21 | **~81%** | warning | Affiner: "leverage", "robust", "nuanced" apparaissent dans du code humain |
| no-format-url | 22 | ~5 | ~17 | **~77%** | error | Affiner: construction d'URL locale/test n'est pas une injection |
| no-glob-reexport | 16 | ~8 | ~8 | **~50%** | warning | Acceptable: `pub(crate) use module::*` est un pattern courant mais discutable |
| no-paraphrase-doc | 9 | ~3 | ~6 | **~67%** | warning | Affiner: "Creates a new X" est une doc valide pour les constructeurs |
| no-silent-fallback | 7 | ~4 | ~3 | **~43%** | warning | Acceptable |
| no-empty-env-secret | 4 | ~1 | ~3 | **~75%** | error | Affiner: usage en test |
| no-client-without-timeout | 2 | ~2 | ~0 | **~0%** | error | OK |
| no-format-path | 2 | ~1 | ~1 | **~50%** | error | OK |
| no-sqlx-runtime | 2 | ~2 | ~0 | **~0%** | error | OK |

### Regles a zero finding (sur 5 repos)

| Regle | Language | Verdict |
|-------|----------|---------|
| no-float-money | rust | Utile mais contexte financier rare dans ces repos |
| no-index-without-if-not-exists | rust | Utile mais pas de SQL dans ces repos |
| no-debug-on-secrets | rust | Pattern rare, garder |
| no-manual-rfc3339 | rust | Pattern rare, garder |

## Top 5 des regles les plus bruyantes

### 1. no-inline-qualified-path (3 166 findings, ~90% FP)

**Probleme** : la regle signale TOUT chemin qualifie (`std::io::Result`, `std::fmt::Display`).
En Rust idiomatique, utiliser le chemin complet dans les impls de traits std est normal :
```rust
impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
```
Ce n'est PAS du slop IA.

**Exemples de FP** :
- `std::fmt::Display`, `std::fmt::Formatter`, `std::fmt::Result` dans les impl Display
- `std::error::Error` dans les impl Error
- `std::io::Result` comme type de retour sans import (courant dans les petits modules)
- `std::pin::Pin`, `std::task::Context`, `std::task::Poll` dans les impl Future

**Action** : ouvrir un ticket pour affiner le pattern. Exclure :
- Chemins dans les signatures d'impl de traits std (Display, Error, Future, Iterator, etc.)
- `build.rs`
- Fichiers de test

### 2. no-unwrap-in-prod (944 findings, ~74% FP)

**Probleme** : la regle ne distingue pas les fichiers de test/bench/example du code de production.
`unwrap()` est idiomatique dans les tests Rust.

**Exemples de FP** :
- `tests/` et fichiers `*_test.rs` : `unwrap()` normal dans les assertions
- `build.rs` : `std::env::var("TARGET").unwrap()` est standard
- `benches/` et `examples/` : code jetable

**Action** : exclure via le chemin de fichier : `test`, `tests`, `benches`, `examples`, `build.rs`.

### 3. test-needs-timeout (883 findings, ~89% FP)

**Probleme** : la regle matche `#[tokio::test]` sans timeout, mais beaucoup de tests tokio sont
des tests unitaires rapides qui n'ont pas besoin de timeout.

**Exemples de FP** :
- Tests unitaires sync wrapes dans `#[tokio::test]` pour le runtime
- Tests de parsing, de conversion, d'assertions simples

**Action** : cette regle est trop opinionnee pour un linter generique. Envisager de la passer
en opt-in ou d'exiger un seuil minimum (e.g. seulement si le test fait du I/O reseau).

### 4. no-unsafe-without-safety (670 findings, ~93% FP)

**Probleme** : la regle ne detecte pas les commentaires `// SAFETY:` existants.
Tokio documente massivement ses blocs unsafe avec `// SAFETY:`, mais la regle les signale quand meme.

**Exemples de FP** :
```rust
// SAFETY: the caller promises that `rd.read` initializes the buffer
unsafe { ... }
```
La regle matche le `unsafe` sans verifier si un commentaire SAFETY precede.

**Action** : bug critique. La regle doit verifier la presence d'un commentaire `// SAFETY:` avant
le bloc unsafe. C'est probablement une limitation du pattern AST qui ne capture pas les commentaires.

### 5. no-trivial-doc (354 findings, ~92% FP)

**Probleme** : le pattern matche "This type" ou "This function" en debut de doc-comment, mais
dans la majorite des cas, la suite du commentaire est une explication utile et non-triviale.

**Exemples de FP** :
- `/// This type is primarily accessed through the [RegistryData] trait.` -- informatif
- `/// This function is similar to sync_all, except that...` -- explique la difference
- `/// This type is structurally identical to std::ops::Range<usize>, but...` -- justifie l'existence

**Action** : affiner le pattern pour ne matcher que quand le doc-comment est UNIQUEMENT "This type/function is X" sans elaboration.

## Regles avec bon taux de precision (<= 30% FP)

Ces regles fonctionnent bien sur du vrai code :

| Regle | Taux FP | Commentaire |
|-------|---------|-------------|
| no-client-without-timeout | ~0% | Precision excellente |
| no-sqlx-runtime | ~0% | Precision excellente |
| no-ignored-result | ~24% | Acceptable pour un warning |

## Synthese

### Bilan initial

- **7 668 findings** sur 5 repos, 671k lignes
- **Taux de FP global estime : ~80%** -- beaucoup trop eleve pour un outil utilisable
- **3 regles concentrent 65% des findings** : no-inline-qualified-path, no-unwrap-in-prod, test-needs-timeout
- **Performance** : excellente, aucun probleme meme sur cargo (343k lignes)

### Corrections appliquees

| Correction | Regle(s) | Impact |
|-----------|----------|--------|
| Exclusion `build.rs`, `*-test-*` crates | no-unwrap-in-prod, no-expect-in-prod | -153 / -39 findings |
| Exclusion benches/examples | no-unsafe-without-safety | -4 findings (limitation ast-grep) |
| Exclusion build.rs, tests, benches, examples + trait impls std (Display, Error, etc.) | no-inline-qualified-path | -1 948 findings |
| Pattern resserre (ligne courte uniquement) | no-trivial-doc | -336 findings |
| Pattern resserre (commentaire court + exclusion BUG/TODO/SAFETY) | no-restated-comment | -326 findings |
| Retrait "comprehensive", "robust", "leverage", "harness", "nuanced" | no-slop-words | -19 findings |
| Retrait "various", exclusion si "such as"/"e.g."/"including" | no-and-more-doc | -52 findings |
| Exclusion `cfg_attr(not(feature), allow(dead_code))` | no-allow-dead-code | -14 findings |
| Exclusion si le type finit par Error/Err/Failure | no-manual-display | a evaluer |
| Ajout `inside: block has: unsafe_block` | no-safety-hallucination | -93 findings |
| Passage en `enabled: false` (opt-in) | pub-fn-needs-tracing | -208 findings |
| Passage en `enabled: false` (opt-in) | test-needs-timeout | -883 findings |

**Resultat global : 7 668 -> 3 587 (-53%)**

### Problemes restants

1. **`no-unsafe-without-safety` (667 findings, estimation ~90% FP)** : limitation structurelle d'ast-grep.
   Le `follows` ne voit que le noeud AST immediatement precedent. Un commentaire `// SAFETY:` separe
   de l'`unsafe` par 2+ lignes (commentaire multi-lignes) n'est pas detecte. Solution : ajout d'une
   logique custom dans le scanner Rust (pas seulement du YAML) pour detecter un `// SAFETY:` dans les
   5 lignes precedant un `unsafe` block.

2. **`no-unwrap-in-prod` (791 findings)** : les crates avec "test" dans le nom (cargo-test-support)
   ne sont pas filtrees car elles sont dans `crates/`, pas dans `tests/`. L'ajout du glob `**/*-test-*/**`
   aide mais ne couvre pas tous les cas. Solution possible : un mecanisme `skip_test_crates: true`
   qui detecte les crates avec `[dev-dependencies]` only ou le mot "test" dans le nom du package.

3. **`no-inline-qualified-path` (1 218 findings)** : encore trop de FP. Les exclusions par trait impl
   ne couvrent pas tous les cas (e.g. `std::sync::atomic::Ordering` utilise inline est idiomatique
   dans certains contextes). Piste : passer en warning-only et ne signaler que les cas avec 3+ segments.

4. **`no-expect-in-prod` (316 findings)** : meme probleme que no-unwrap-in-prod pour les crates test.

### Priorite pour la suite

1. Logique custom dans le scanner pour `no-unsafe-without-safety` (detection commentaire multi-lignes)
2. Mecanisme de detection de crates "test" par metadata Cargo
3. Affiner `no-inline-qualified-path` pour les patterns `std::sync::atomic::*`
