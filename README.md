# AI Git Assist (Python)

A Python CLI for AI-powered conventional commits, security checks, and optional test/README generation.

## Workflow

1. **Staged-only by default** — Only your staged changes are committed. No automatic `git add .`.
2. Staged diff is scanned for **sensitive data** (AWS keys, tokens, private keys, etc.).
3. **Conventional Commit** message is generated from the diff.
4. Optional: generate tests, update README, send Slack notification (each off by default).
5. Commit and push (push uses upstream branch when set, else `origin/<branch>`).

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
| `repo` | Path to git repo (default: current directory) |
| `--model` | OpenAI model (default: `gpt-4o-mini` or `OPENAI_MODEL`) |
| `--max-diff-chars` | Max diff size sent to AI (default: 40000) |
| `--all` | Stage all changes before commit (default: staged-only) |
| `--dry-run` | Print security findings, commit message, and affected files; no write/commit/push |
| `--no-push` | Do not push after commit |
| `--non-interactive` | CI mode: auto-accept commit; skip README/tests unless enabled; security violations exit non-zero unless `--force` |
| `--force` | In non-interactive mode, proceed despite security violations |
| `--gen-tests` | Generate test cases for changed code (off by default) |
| `--update-readme` | Update or create README and append changelog (off by default) |
| `--slack` | Send commit message to Slack via `SLACK_WEBHOOK_URL` (off by default) |

## Environment

- **`OPENAI_API_KEY`** (required for commit message generation)
- **`OPENAI_MODEL`** (optional, default: `gpt-4o-mini`)
- **`SLACK_WEBHOOK_URL`** (optional, used only with `--slack`)

## Push behavior

- Uses **upstream** when set (`git rev-parse --symbolic-full-name @{u}`), e.g. `origin/main`.
- If no upstream is configured, pushes to `origin/<current-branch>`.

## Error messages

- **No staged changes** — Prints exact suggestions: `git add <file>`, `git add -p`, or `ai-git-assist --all`.
- **Missing `OPENAI_API_KEY`** — Prints: `export OPENAI_API_KEY='your-api-key'`.
- **`git commit` fails** — Full stderr is shown.

## Examples

```bash
# Interactive, staged-only
git add -p
ai-git-assist

# Dry run to see message and security
ai-git-assist --dry-run

# CI: commit and push, no extras
export OPENAI_API_KEY=...
ai-git-assist --non-interactive

# CI with tests and README
ai-git-assist --non-interactive --gen-tests --update-readme --no-push
```
