## Setagaya Documentation Style Guide

Purpose: Keep docs consistent, searchable, and easy to maintain.

Headlines and structure
- Use H1 only for page title (one per file). Use H2/H3 for sections.
- Keep sections short; prefer lists for steps.

Writing style
- Use active voice and second person for instructions ("Run `make` to build...").
- Keep sentences short and focused.
- Use code fences for commands and config blocks.

Code blocks
- Indicate language where appropriate (```bash, ```yaml, ```json).
- Show minimal input and expected output where helpful.

Links and references
- Use relative links for internal pages (no absolute URLs to the repo).
- Update links when moving files; run link-check CI before merging.

Front-matter
- Use the template in `docs/templates/FRONT_MATTER.md`.

Examples and commands
- Provide copy-pasteable commands in fenced code blocks.
- Prefer `zsh`-compatible examples for developers on macOS/Linux.

Images and media
- Prefer text-first documentation. Use images only when essential and include alt text.

Accessibility
- Use descriptive link text. Avoid "click here".
- Add alt text for images and captions where useful.

Review cadence
- Mark `last_reviewed` in front-matter when completed.
- Use `status: review` to indicate the doc needs peer review.

Maintenance
- New technical terms must be added to `.github/wordlist.txt` before merging docs that introduce them.

Contact
- For doc-related questions open an issue in the `docs` tracker or tag `@doc-maintainers`.
