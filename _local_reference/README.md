# Local reference (not synced to Git)

Everything in this directory **except this file** is listed in the repo root `.gitignore` and will **never** be committed or pushed.

Use it for:

- NXP / SE050 datasheets and application notes (PDF, HTML exports)
- Legacy or third-party source you are **not** allowed to redistribute
- Notes, captures, and scratch work

Suggested layout (optional — create as needed):

```text
_local_reference/
  README.md               (this file — tracked)
  datasheet/              (ignored) — PDFs from NXP
  nxp-nano-package/       (ignored) — git clone of NXPPlugNTrust/nano-package
  legacy_code/            (ignored) — zip/tar or copied trees from old projects
  notes.md                (ignored)
```

`nxp-nano-package` is **protocol reference only**. Do not compile it into
pw-controller-sw. The product SE path is `hf-se050` T=1 +
`se050_scp03.hpp` / `se050_scp03_crypto.hpp`. Nano's Cortex-A / G0
middleware would be a second I²C stack and would tempt compiled-in NXP
default SCP03 keys (forbidden).

When implementing `inc/` and `src/`, translate requirements from here into **clean-room** code in tracked paths only.
