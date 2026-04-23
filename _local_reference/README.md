# Local reference (not synced to Git)

Everything in this directory **except this file** is listed in the repo root `.gitignore` and will **never** be committed or pushed.

Use it for:

- NXP / SE050 datasheets and application notes (PDF, HTML exports)
- Legacy or third-party source you are **not** allowed to redistribute
- Notes, captures, and scratch work

Suggested layout (optional — create as needed):

```text
_local_reference/
  README.md          (this file — tracked)
  datasheet/         (ignored) — PDFs from NXP
  legacy_code/       (ignored) — zip/tar or copied trees from old projects
  notes.md           (ignored)
```

When implementing `inc/` and `src/`, translate requirements from here into **clean-room** code in tracked paths only.
