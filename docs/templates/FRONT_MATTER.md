
<!-- FRONT MATTER template for Setagaya documentation -->

Place the YAML block below at the very top of a markdown file. Use it to populate the docs index and drive status checks.

```yaml
---
title: "Short human-friendly title"
description: "One-line summary (used in search and index)"
kind: "guide"        # one of: guide, reference, api, ops, security, contrib, appendix
status: "draft"      # draft | review | stable | deprecated
owner: "@team-or-user"
last_reviewed: "2025-09-19"
tags: ["rbac","deployment"]
---
```

Notes:
- Keep `title` concise (< 60 chars). Use sentence case.
- `description` should be a single sentence.
- `kind` determines where the doc will live in the site navigation.
- `status` is used for staging and release notes; update when the doc is reviewed.
- `owner` is a GitHub username or team handle responsible for the content.

Policy reminder: update `.github/wordlist.txt` before introducing new domain-specific terms (product names, acronyms) so spellcheck CI won't fail.
