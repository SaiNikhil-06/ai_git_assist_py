```markdown
# AI Git Assist (Python)

A Python CLI tool that enhances your Git workflow with AI-powered features, including conventional commits, security checks, and optional test and README generation.

## Workflow

1. **Staged-only by default** — Only your staged changes are committed. No automatic `git add .`.
2. The staged diff is scanned for **sensitive data** (e.g., AWS keys, tokens, private keys).
3. An AI-generated **Conventional Commit** message is created based on the diff.
4. Optional features include generating tests, updating the README, and sending Slack notifications (all off by default).
5. Commits are made and pushed (pushes to the upstream branch if set; otherwise, to `origin/<branch>`).

## Features

- **AI-generated Conventional Commits** from your staged diff, ensuring consistent and review-friendly messages.
- **AI-aware security checks** that scan staged changes for common secret patterns (e.g., Token IDs, API Keys) before committing.
- **AI-assisted test generation** (`--gen-tests`) to help create basic coverage for modified code.
- **AI-assisted README updates** (`--update-readme`) that append changelog entries automatically.
- **AI-to-Slack notifications** (`--slack`) that send a human-readable update via webhook after a successful commit.
- **CI-ready mode** (`--non-interactive`) for automated pipelines with predictable behavior.
- **Smart push behavior**: pushes to upstream if set; otherwise, it defaults to `origin/<branch>`.

## Install

```bash
pip install -e .
# or
pip install .
```

## Usage

```bash
# Staged-only (default): stage files yourself, then run
git add path/to/file.py
ai-git-assist

# Stage everything and run
ai-git-assist --all

# See what would happen without writing or committing
ai-git-assist --dry-run

# Commit but do not push
ai-git-assist --no-push

# CI / non-interactive: auto-accept message and commit; skip README/tests unless enabled
ai-git-assist --non-interactive

# With extras
ai-git-assist --gen-tests --update-readme --slack
```

## Flags

| Flag | Description |
|------|-------------|
| `repo` | Path to the Git repository (default: current directory) |
| `--model` | OpenAI model (default: `gpt-4o-mini` or `OPENAI_MODEL`) |
| `--max-diff-chars` | Maximum diff size sent to AI (default: 40000) |
| `--all` | Stage all changes before committing (default: staged-only) |
| `--dry-run` | Print security findings, commit message, and affected files; no write/commit/push |
| `--no-push` | Do not push after commit |
| `--non-interactive` | CI mode: auto-accept commit; skip README/tests unless enabled; security violations exit non-zero unless `--force` |
| `--force` | In non-interactive mode, proceed despite security violations |
| `--gen-tests` | Generate test cases for changed code (off by default) |
| `--update-readme` | Update or create README and append changelog (off by default) |
| `--slack` | Send commit message to Slack via `SLACK_WEBHOOK_URL` (off by default) |

## Environment Variables

- **`OPENAI_API_KEY`** (required for commit message generation)
- **`OPENAI_MODEL`** (optional; defaults to `gpt-4o-mini`)
- **`SLACK_WEBHOOK_URL`** (optional; used only with `--slack`)

## Push Behavior

- Uses **upstream** when set (`git rev-parse --symbolic-full-name @{u}`), e.g., `origin/main`.
- If no upstream is configured, it pushes to `origin/<current-branch>`.

## Error Messages

- **No staged changes** — Provides suggestions: `git add <file>`, `git add -p`, or `ai-git-assist --all`.
- **Missing `OPENAI_API_KEY`** — Suggests: `export OPENAI_API_KEY='your-api-key'`.
- **`git commit` fails** — Displays full stderr output.

## Examples

```bash
# Interactive, staged-only
git add -p
ai-git-assist

# Dry run to see message and security findings
ai-git-assist --dry-run

# CI: commit and push, no extras
export OPENAI_API_KEY=...
ai-git-assist --non-interactive

# CI with tests and README updates
ai-git-assist --non-interactive --gen-tests --update-readme --no-push
```
```

## Features / Changelog
- **2026-02-15 10:47**: Readme modified
