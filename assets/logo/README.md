# slopguard logo

The AI sparkle, sliced clean in a single stroke. The name is always lowercase: `slopguard`.

## Files

| File | What it is |
|---|---|
| `slopguard-logo-light.svg` | Horizontal logo for light backgrounds (red symbol, ink wordmark) |
| `slopguard-logo-dark.svg` | Horizontal logo for dark backgrounds (red symbol, paper wordmark) |
| `slopguard-banner.png` | 2560 x 640 banner with its own dark background, readable on any theme |
| `slopguard-icon.svg` | Square icon: red symbol on a rounded ink tile (200 x 200 viewBox) |
| `slopguard-avatar.png` | 512 x 512 avatar: red symbol on a full ink square, safe for circular crops |
| `slopguard-social.png` | 1280 x 640 card: logo, tagline, `#![deny(slop)]` |

## What to use where

### README

The root `README.md` already uses the header below. GitHub picks the light or dark SVG from the
viewer's theme. GitLab strips `<picture>` and `<source>`, so it shows the `<img>` fallback, the
banner, which reads on both GitLab themes.

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/slopguard-logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/logo/slopguard-logo-light.svg">
  <img alt="slopguard" src="assets/logo/slopguard-banner.png" width="560">
</picture>
```

Crate READMEs published on crates.io need an absolute URL (it resolves once the file is on `main`):

```html
<img alt="slopguard" width="560"
     src="https://gitlab.com/ThomasTartrau/slopguard/-/raw/main/assets/logo/slopguard-banner.png">
```

### Portfolio (tartrau.fr project page)

- Project logo: `slopguard-icon.svg`, copied to the site as `/logos/slopguard.svg`. It follows the
  same template as the other project logos (200 viewBox, 180 tile, radius 40) and works in the light
  and dark themes without a variant.
- Project image: a real screenshot of `slopguard scan` in a terminal matches the other project
  pages best; `slopguard-social.png` works as a fallback and as the Open Graph image.

### LinkedIn

- Project section of the profile, or a post about slopguard: `slopguard-social.png` as the media.
- LinkedIn page logo, if a page is ever created: `slopguard-avatar.png`.

### GitLab

- Project avatar: `slopguard-avatar.png`, in Settings > General > Project avatar (GitLab
  recommends 192 x 192 and 200 KB at most; it resizes the file).

### GitHub

- A repository has no icon. Set `slopguard-social.png` in Settings > General > Social preview; it
  shows in link previews on LinkedIn, Slack, X and others.
- Organisation or account avatar, only if one is dedicated to slopguard: `slopguard-avatar.png`.

## Colours

| Name | HEX | Use |
|---|---|---|
| Red | `#EE2737` | The symbol only |
| Ink | `#0E0F12` | Wordmark on light backgrounds, dark tiles |
| Paper | `#F4F3EF` | Wordmark on dark backgrounds |

Keep clear space around the logo at least as tall as the `o` of the wordmark. Don't stretch,
rotate, recolour, add effects, retype the wordmark in a font, or change the angle of the cut.
