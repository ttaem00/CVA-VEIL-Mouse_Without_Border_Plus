# VEIL MWBP — Agent & Multi-LLM Operating Guide

This public repository (`ttaem00/CVA-VEIL-Mouse_Without_Border_Plus`) contains **VEIL · MWBP**, a multi-PC keyboard, mouse, clipboard, and file-sharing utility for Windows x64.

## 1. Core Invariants & Safety Boundaries

- Preserve existing peer connections, monitor layouts, hotkeys, transfer history, and portable/installed upgrade recovery ([App/Portable/PortableInstallLifecycle.cs](App/Portable/PortableInstallLifecycle.cs)).
- Preserve emergency local input return (`Ctrl+Alt+Backspace`) and input-recovery flows; never weaken connection-code verification or firewall/network consent boundaries.
- Keep [LICENSE](LICENSE) (MIT), [NOTICE.md](NOTICE.md), icon provenance (`validate-icon.ps1`, `docs/assets/veil-family-source.json`), and anonymized documentation assets intact. Never commit machine-specific paths, personal PC names, credentials, or raw logs.

## 2. Build & Validation Commands

Run from PowerShell 7 (`pwsh.exe`):

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ./validate-icon.ps1
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ./build.ps1 -Configuration Release -Platform x64 -RunTests
```

- Packaging/release scripts (`publish-portable.ps1` and installer builders) are separate from source unit tests; record installer SHA-256 and version readback separately from local test passes.

## 3. Multi-LLM Coexistence (`Codex` · `Claude Code` · `Antigravity`)

- `AGENTS.md` is the single canonical instruction file across all coding agents; do not create duplicate root instruction files.
- Preserve any uncommitted state in primary checkouts. Develop on isolated issue branches/worktrees (`codex/issue-<N>-<slug>`) and merge via **merge-commit PRs only** (never push directly to `main`, never squash/rebase, never bypass hooks with `--no-verify`).
- Run an independent `/adversarial-review` and attach real build/test output before merging.
