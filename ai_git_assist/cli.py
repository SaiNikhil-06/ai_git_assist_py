"""AI Git Assist (Python)

A Python re-implementation of the Java Spring Boot "AI Git Assist" CLI.

Features:
- AI-generated Conventional Commit message from staged diff (staged-only by default)
- Optional AI-generated tests (--gen-tests)
- Sensitive information detection in staged diff
- Optional README.md generation/update (--update-readme)
- Optional Slack webhook notification (--slack)

Env vars:
- OPENAI_API_KEY (required)
- OPENAI_MODEL (optional, default: gpt-4o-mini)
- SLACK_WEBHOOK_URL (optional, used only with --slack)

Usage:
  python -m ai_git_assist [path/to/repo] [--dry-run] [--all] [--no-push] ...
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional


# -----------------------------
# Console formatting
# -----------------------------

BANNER = (
    "\n╔══════════════════════════════════════════════════════════╗\n"
    "║              AI Git Assist (Python)                     ║\n"
    "║     AI-Powered Commit Messages & Test Generation         ║\n"
    "╚══════════════════════════════════════════════════════════╝\n"
)

SEP = "═══════════════════════════════════════════════════════════"


# -----------------------------
# Models
# -----------------------------

@dataclass(frozen=True)
class ValidationResult:
    is_safe: bool
    violations: List[str]


# -----------------------------
# Git helpers
# -----------------------------

def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command inside repo, returning CompletedProcess."""
    cmd = ["git", "-C", str(repo), *args]
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def is_git_repo(repo: Path) -> bool:
    return repo.is_dir() and (repo / ".git").is_dir()


def has_staged_changes(repo: Path) -> bool:
    cp = run_git(repo, "diff", "--cached", "--name-only", check=False)
    return cp.returncode == 0 and bool(cp.stdout.strip())


def stage_all(repo: Path) -> None:
    run_git(repo, "add", ".")


def get_staged_diff(repo: Path) -> str:
    cp = run_git(repo, "diff", "--cached")
    return cp.stdout or ""


def get_staged_files(repo: Path) -> List[str]:
    cp = run_git(repo, "diff", "--cached", "--name-only")
    return [f.strip() for f in (cp.stdout or "").strip().splitlines() if f.strip()]


def current_branch(repo: Path) -> str:
    cp = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    return cp.stdout.strip()


def get_push_target(repo: Path) -> Optional[str]:
    """Return upstream ref (e.g. origin/main) or None; then caller can use origin/<branch>."""
    cp = run_git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False)
    if cp.returncode == 0 and cp.stdout.strip():
        return cp.stdout.strip()
    return None


def commit_changes(repo: Path, commit_message: str) -> None:
    """Commit currently staged changes only (no git add)."""
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write(commit_message.strip() + "\n")
        msg_path = f.name

    try:
        run_git(repo, "commit", "-F", msg_path)
    finally:
        try:
            os.unlink(msg_path)
        except OSError:
            pass


def push_changes(repo: Path, branch: str) -> None:
    upstream = get_push_target(repo)
    if upstream:
        remote, ref = upstream.split("/", 1)
    else:
        remote, ref = "origin", branch
    run_git(repo, "push", remote, ref)


def summarize_diff_for_ai(diff: str, file_list: List[str], max_chars: int) -> str:
    """Produce a deterministic summary for huge diffs: file list + top hunks per file."""
    if not diff or len(diff) <= max_chars:
        return diff

    # Build summary: header with file list, then first N hunks of each file
    lines = diff.splitlines()
    summary_parts: List[str] = [
        "# Changed files:",
        "\n".join(f"  - {f}" for f in file_list),
        "",
        "# Diff (summary — first hunks per file):",
        "",
    ]
    current_file: Optional[str] = None
    current_hunk: List[str] = []
    hunks_in_file = 0
    max_hunks_per_file = 5
    budget = max_chars - sum(len(s) + 1 for s in summary_parts)

    def flush_hunk() -> None:
        nonlocal current_hunk, budget
        if current_hunk:
            block = "\n".join(current_hunk) + "\n"
            if len(block) <= budget:
                summary_parts.append(block)
                budget -= len(block)
            current_hunk.clear()

    i = 0
    while i < len(lines) and budget > 100:
        line = lines[i]
        if line.startswith("+++ b/"):
            flush_hunk()
            current_file = line.replace("+++ b/", "").strip()
            hunks_in_file = 0
            summary_parts.append(f"\n--- {current_file} ---\n")
            budget -= len(summary_parts[-1])
            i += 1
            continue
        if line.startswith("@@"):
            hunks_in_file += 1
            if hunks_in_file > max_hunks_per_file:
                current_hunk = []
                i += 1
                while i < len(lines) and not lines[i].startswith("@@"):
                    i += 1
                continue
            flush_hunk()
            current_hunk = [line]
            i += 1
            continue
        if current_hunk:
            current_hunk.append(line)
        i += 1
    flush_hunk()

    summary_parts.append("\n... [rest of diff omitted] ...")
    return "\n".join(summary_parts)


# -----------------------------
# Security validation
# -----------------------------

SENSITIVE_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key detected"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub Personal Access Token detected"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "Private key detected"),
    (
        re.compile(
            r"(?i)(api[_-]?key|password|secret|token)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?"
        ),
        "API key, password, or secret detected",
    ),
    (re.compile(r"(?i)[/\\]\.env"), ".env file detected"),
]


def validate_diff(diff: str) -> ValidationResult:
    if not diff or not diff.strip():
        return ValidationResult(True, [])

    violations: List[str] = []
    for pattern, label in SENSITIVE_PATTERNS:
        if pattern.search(diff):
            violations.append(label)

    return ValidationResult(is_safe=(len(violations) == 0), violations=violations)


# -----------------------------
# File utilities (test file heuristic)
# -----------------------------

def extract_changed_file(diff: str) -> Optional[str]:
    """Match the Java logic: first '+++ b/<file>' containing 'src/' and not tests/markdown/json/xml."""
    for line in diff.splitlines():
        if line.startswith("+++") and "src/" in line:
            file_path = line.replace("+++ b/", "").strip()
            if (
                "Test" not in file_path
                and "test" not in file_path
                and not file_path.endswith((".md", ".txt", ".json", ".xml"))
            ):
                return file_path
    return None


def generate_test_file_path(source_file: str) -> str:
    """Generate a test file path using the same conventions as the Java version."""
    p = Path(source_file)
    ext = p.suffix
    base_path = str(p.with_suffix(""))

    if not ext:
        return f"tests/{source_file}_test"

    if ext == ".java":
        java_path = base_path.replace("src/main/java/", "")
        return f"src/test/java/{java_path}Test.java"

    if ext == ".py":
        python_path = base_path.replace("src/", "").replace("/", "_")
        return f"tests/test_{python_path}.py"

    if ext in (".js", ".ts"):
        return f"{base_path}.test{ext}"

    generic_path = base_path.replace("src/", "")
    return f"tests/{generic_path}_test{ext}"


# -----------------------------
# README handling
# -----------------------------

README_FILE = "README.md"
CHANGELOG_HEADER = "## Features / Changelog"


def append_changelog(readme_path: Path, commit_message: str) -> None:
    lines = readme_path.read_text(encoding="utf-8").splitlines()
    summary = commit_message.splitlines()[0] if commit_message.strip() else "(no summary)"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    entry = f"- **{timestamp}**: {summary}"

    inserted = False
    for i, line in enumerate(lines):
        if line.strip() == CHANGELOG_HEADER:
            lines.insert(i + 1, entry)
            inserted = True
            break

    if not inserted:
        lines.append("")
        lines.append(CHANGELOG_HEADER)
        lines.append(entry)

    readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# -----------------------------
# Slack
# -----------------------------

def send_slack_notification(text: str) -> None:
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook:
        print("⚠️  SLACK_WEBHOOK_URL not set; skipping Slack.", file=sys.stderr)
        return

    try:
        import requests  # type: ignore
        requests.post(webhook, json={"text": text}, timeout=10)
    except Exception as e:
        print(f"Failed to send Slack notification: {e}", file=sys.stderr)

def build_repo_context(repo: Path, max_files: int = 200, max_total_chars: int = 40000) -> str:
    """
    Build a compact repo snapshot for the LLM:
    - file list from git (respects ignore)
    - excerpts of key files (small and high-signal)
    """
    cp = run_git(repo, "ls-files", check=False)
    files = [f.strip() for f in (cp.stdout or "").splitlines() if f.strip()]
    files = files[:max_files]

    key_names = {
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "Pipfile", "poetry.lock", "environment.yml",
        "package.json", "Makefile", "Dockerfile",
        "README.md",
    }

    # prioritize: key files + top-level python/js + notebooks
    prioritized = []
    for f in files:
        p = Path(f)
        if p.name in key_names:
            prioritized.append(f)
    for f in files:
        if f in prioritized:
            continue
        if f.endswith((".py", ".js", ".ts", ".ipynb")) and ("/.venv/" not in f) and ("/venv/" not in f):
            prioritized.append(f)

    chunks = []
    chunks.append("REPO FILES:\n" + "\n".join(files))

    budget = max_total_chars - len(chunks[0])
    for f in prioritized:
        if budget <= 1000:
            break
        path = repo / f
        if not path.exists() or path.is_dir():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Don’t dump huge notebooks; just take the head.
        snippet = raw[:6000]
        block = f"\n\n===== {f} (excerpt) =====\n{snippet}"
        if len(block) > budget:
            continue
        chunks.append(block)
        budget -= len(block)

    return "\n".join(chunks)


# -----------------------------
# OpenAI integration
# -----------------------------


class AIClient:
    def __init__(self, model: str):
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

        # Lazy import so the tool can still run security checks without OpenAI.
        from openai import OpenAI  # type: ignore

        self._client = OpenAI(api_key=api_key)
        self._model = model

    def _call(self, instructions: str, prompt: str, temperature: float) -> str:
        """Use the Responses API and return aggregated output_text."""
        resp = self._client.responses.create(
            model=self._model,
            instructions=instructions,
            input=prompt,
            temperature=temperature,
        )
        text = getattr(resp, "output_text", "")
        return (text or "").strip()

    def generate_commit_message(self, diff: str) -> str:
        prompt = (
            "You are an expert software developer.\n"
            "Here is a git diff of staged changes:\n\n"
            f"{diff}\n\n"
            "Write a Conventional Commit message:\n"
            "- One of: feat:, fix:, docs:, refactor:, test:, chore:, perf:\n"
            "- Summary line <= 72 chars\n"
            "- Optional short body with bullet points\n"
            "- Do NOT include markdown code fences or backticks"
        )
        return self._call(
            instructions="You write excellent, concise conventional commits.",
            prompt=prompt,
            temperature=0.2,
        )

    def generate_test_cases(self, diff: str, changed_file: str) -> str:
        prompt = (
            "You are an expert software tester.\n"
            "Here is a git diff showing code changes:\n\n"
            f"{diff}\n\n"
            f"Generate 1-2 concise test cases for the changed functionality in: {changed_file}\n"
            "- Use appropriate testing framework for the file's language\n"
            "- Focus on main functionality\n"
            "- Return only test code, no explanations\n"
            "- Do NOT wrap in code fences"
        )
        return self._call(
            instructions="You write excellent, practical test cases.",
            prompt=prompt,
            temperature=0.3,
        )

    def generate_readme(self, project_name: str, env_keys: List[str]) -> str:
        env_list = "\n".join([f"- `{k}`" for k in env_keys]) if env_keys else "- (none)"
        prompt = (
            f"Write a professional GitHub README.md for a software project called \"{project_name}\".\n"
            "Include these sections in this order:\n\n"
            "# <Title>\n"
            "One-paragraph description of what the project does.\n\n"
            "## Features\n"
            "Short bullet list of key capabilities.\n\n"
            "## Installation\n"
            "Exact steps to install the project based on its technology stack.\n\n"
            "## Usage\n"
            "How to run the project with primary commands.\n\n"
            "## Configuration\n"
            f"Environment variables if needed:\n{env_list}\n\n"
            "## Development\n"
            "- How to run locally\n"
            "- How to run tests (if any)\n"
            "- Coding style standards\n\n"
            "## Features / Changelog\n"
            "Add a single placeholder bullet here."
        )
        return self._call(
            instructions="You write excellent, practical READMEs for real projects.",
            prompt=prompt,
            temperature=0.2,
        )


    def update_readme(self, repo_context: str, current_readme: str, commit_message: str, diff: str) -> str:
        prompt = (
            "You are updating a GitHub README.md.\n"
            "You MUST make it accurate to what the repository actually does.\n\n"
            "Repo context (file list + excerpts):\n"
            f"{repo_context}\n\n"
            "Current README.md:\n"
            f"{current_readme}\n\n"
            "New commit message:\n"
            f"{commit_message}\n\n"
            "Git diff summary:\n"
            f"{diff}\n\n"
            "Instructions:\n"
            "- Rewrite/improve the README so it matches the repo’s real purpose and files.\n"
            "- Fix/remove obviously nonsense bullets (keep useful history).\n"
            "- Keep existing section headers if present, but improve content.\n"
            "- Ensure Features are real and specific (based on repo context).\n"
            "- Usage should include the commands a user would actually run.\n"
            "- Configuration should mention env vars only if the repo truly uses them.\n"
            "- Do NOT wrap in code fences.\n"
            "Return the full updated README.md."
        )
        return self._call(
            instructions="You write accurate, practical READMEs based on the repository contents.",
            prompt=prompt,
            temperature=0.2,
        )


    def generate_slack_update(
        self,
        repo_name: str,
        branch: str,
        commit_sha: str,
        commit_message: str,
        staged_files: List[str],
        diff_summary: str,
        ) -> str:
        files = "\n".join([f"- {f}" for f in staged_files]) if staged_files else "- (none)"
        prompt = (
            "Write a Slack update for a complete repo change.\n"
            "Goal: human, useful, and specific. Not generic.\n\n"
            f"Repo: {repo_name}\n"
            f"Branch: {branch}\n"
            f"Commit: {commit_sha}\n\n"
            "Commit message:\n"
            f"{commit_message}\n\n"
            "Files changed:\n"
            f"{files}\n\n"
            "Diff summary:\n"
            f"{diff_summary}\n\n"
            "Slack message rules:\n"
            "- 6 to 12 lines max\n"
            "- Start with a 1-line headline with an emoji\n"
            "- Then 3-6 bullets: what changed + why it matters\n"
            "- Add 1 line: 'Impact/Risk:' with honest risk level\n"
            "- Add 1 line: 'Next:' with a sensible follow-up\n"
            "- No code fences, no backticks\n"
        )
        return self._call(
            instructions="You write concise, practical Slack engineering updates.",
            prompt=prompt,
            temperature=0.2,
        )



# -----------------------------
# CLI interaction
# -----------------------------

def ask_yes_no(prompt: str) -> bool:
    while True:
        resp = input(prompt).strip().lower()
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False
        print("Please enter 'y' or 'n'")


def edit_commit_message(original: str) -> str:
    print("Enter your commit message (press Enter twice to finish, or 'cancel' to keep original):")
    print("Current message:")
    print(original)
    print("\nEnter new message:")

    new_lines: List[str] = []
    empty = 0
    while True:
        try:
            line = input()
        except EOFError:
            break

        if line.strip().lower() == "cancel":
            return original

        if line == "":
            empty += 1
            if empty >= 2:
                break
            new_lines.append("")
        else:
            empty = 0
            new_lines.append(line)

    edited = "\n".join(new_lines).strip()
    return edited if edited else original


def ensure_readme(repo: Path, commit_message: str, diff: str, ai: AIClient) -> None:
    readme_path = repo / README_FILE
    project_name = repo.name

    # Build repo context so README updates match what the repo actually contains
    repo_context = build_repo_context(repo)

    if not readme_path.exists():
        # Only include env vars in README if you really want them documented.
        # For most repos (like CampusRecruitmentML), env_keys can be empty.
        content = ai.generate_readme(project_name, env_keys=[])
        readme_path.write_text(content.strip() + "\n", encoding="utf-8")
    else:
        current = readme_path.read_text(encoding="utf-8")
        updated = ai.update_readme(repo_context, current, commit_message, diff)
        readme_path.write_text(updated.strip() + "\n", encoding="utf-8")

    append_changelog(readme_path, commit_message)



# -----------------------------
# Main
# -----------------------------

OPENAI_KEY_HINT = (
    "Set it with: export OPENAI_API_KEY='your-api-key'"
)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai-git-assist",
        add_help=True,
        description="AI-powered commit helper: security scan, conventional commit message, optional tests/README/Slack.",
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=os.getcwd(),
        help="Path to git repository (default: current directory)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        help="OpenAI model (default: env OPENAI_MODEL or gpt-4o-mini)",
    )
    parser.add_argument(
        "--max-diff-chars",
        type=int,
        default=int(os.environ.get("AI_MAX_DIFF_CHARS", "40000")),
        help="Max diff chars sent to AI (default: 40000)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Stage all changes before commit (default: staged-only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print security findings, commit message, and affected files; do not write, commit, or push",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Do not push after commit",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="CI mode: auto-accept commit, skip README/tests unless enabled; security violations exit non-zero unless --force",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="In non-interactive mode, proceed despite security violations",
    )
    parser.add_argument(
        "--gen-tests",
        action="store_true",
        help="Generate test cases for changed code (off by default)",
    )
    parser.add_argument(
        "--update-readme",
        action="store_true",
        help="Update or create README and append changelog (off by default)",
    )
    parser.add_argument(
        "--slack",
        action="store_true",
        help="Send commit message to Slack (requires SLACK_WEBHOOK_URL; off by default)",
    )

    args = parser.parse_args(argv)
    repo = Path(args.repo).expanduser().resolve()
    dry_run = args.dry_run
    non_interactive = args.non_interactive

    print(BANNER)

    if not repo.exists() or not repo.is_dir():
        print(f"\n❌ ERROR: Repository path does not exist: {repo}\n", file=sys.stderr)
        return 1

    if not is_git_repo(repo):
        print(f"\n❌ ERROR: Not a Git repository: {repo}", file=sys.stderr)
        print("Please run this tool from within a Git repo (or run 'git init')\n", file=sys.stderr)
        return 1

    if args.all:
        stage_all(repo)

    if not has_staged_changes(repo):
        print("\n❌ ERROR: No staged changes found.\n", file=sys.stderr)
        print("Stage files first, for example:", file=sys.stderr)
        print("  git add <file>        # stage specific files", file=sys.stderr)
        print("  git add -p            # stage interactively", file=sys.stderr)
        print("  ai-git-assist --all   # stage everything and run\n", file=sys.stderr)
        return 1

    diff = get_staged_diff(repo)
    if not diff.strip():
        print("\n❌ ERROR: No changes detected in staged files.\n", file=sys.stderr)
        return 1

    staged_files = get_staged_files(repo)

    # Deterministic diff for AI: summarize if huge
    max_chars = args.max_diff_chars
    diff_for_ai = summarize_diff_for_ai(diff, staged_files, max_chars)

    # Security validation
    print("\nValidating changes for sensitive information...")
    validation = validate_diff(diff)

    if not validation.is_safe:
        print("⚠️  WARNING: Security issues detected!\n")
        print("SECURITY WARNING: Sensitive information detected in staged changes!", file=sys.stderr)
        for v in validation.violations:
            print(f"  - {v}", file=sys.stderr)
        if dry_run:
            pass  # Continue to show dry-run output; no prompt, no exit
        elif non_interactive and not dry_run:
            if not args.force:
                print("\nExiting (use --force to override in non-interactive mode).\n", file=sys.stderr)
                return 1
        else:
            print("\nWARNING: Proceeding may expose sensitive data.\n", file=sys.stderr)
            if not ask_yes_no("Continue anyway? (y/n): "):
                print("\nCommit cancelled.\n")
                return 0
            print("\nProceeding with commit (user acknowledged risk)...\n")
    else:
        print("✅ Security validation passed.\n")

    if dry_run:
        print(SEP)
        print("                    DRY RUN")
        print(SEP)
        print("\nFiles affected:")
        for f in staged_files:
            print(f"  - {f}")
        if not validation.is_safe:
            print("\n(Dry run: security issues would block commit unless --force.)")
        print()

    # Initialize AI client (after security so dry-run can show findings without key)
    try:
        ai = AIClient(model=args.model)
    except RuntimeError as e:
        if dry_run:
            print("(Dry run: set OPENAI_API_KEY to see generated commit message.)\n")
            return 0
        print(f"\n❌ ERROR: {e}\n", file=sys.stderr)
        print(OPENAI_KEY_HINT + "\n", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n", file=sys.stderr)
        return 1

    # Test generation (only if --gen-tests or interactive and user says yes)
    do_gen_tests = args.gen_tests
    if not non_interactive and not do_gen_tests:
        print()
        do_gen_tests = ask_yes_no("Generate test cases for functionality changes? (y/n): ")

    if do_gen_tests and not dry_run:
        print("\nGenerating test cases for functionality changes...\n")
        changed = extract_changed_file(diff)
        if changed:
            try:
                test_code = ai.generate_test_cases(diff_for_ai, changed)
                if not non_interactive:
                    print(SEP)
                    print("                    GENERATED TEST CASES")
                    print(SEP + "\n")
                    print(test_code)
                    print("\n" + SEP + "\n")
                    if not ask_yes_no("Save test file? (y/n): "):
                        print("\nTest file not saved.\n")
                    else:
                        test_path_rel = generate_test_file_path(changed)
                        test_path = repo / test_path_rel
                        test_path.parent.mkdir(parents=True, exist_ok=True)
                        test_path.write_text(test_code.strip() + "\n", encoding="utf-8")
                        run_git(repo, "add", test_path_rel)
                        print(f"\n✅ Test saved and staged: {test_path_rel}\n")
                else:
                    test_path_rel = generate_test_file_path(changed)
                    test_path = repo / test_path_rel
                    test_path.parent.mkdir(parents=True, exist_ok=True)
                    test_path.write_text(test_code.strip() + "\n", encoding="utf-8")
                    run_git(repo, "add", test_path_rel)
                    print(f"✅ Test saved and staged: {test_path_rel}\n")
            except Exception as e:
                print(f"\n❌ ERROR: Could not generate tests: {e}\n", file=sys.stderr)
        else:
            print("\nNo suitable source file found for test generation.\n")
    elif do_gen_tests and dry_run:
        print("(Dry run: would generate tests for changed file.)\n")

    # Commit message generation
    print("Generating commit message...")
    commit_message = ai.generate_commit_message(diff_for_ai)
    print("✅ Done.\n")

    print(SEP)
    print("                    COMMIT MESSAGE")
    print(SEP + "\n")
    print(commit_message)
    print("\n" + SEP + "\n")

    if dry_run:
        print("(Dry run: no files written, no commit, no push.)\n")
        return 0

    edit_msg = False
    if not non_interactive:
        edit_msg = ask_yes_no("Edit message? (y/n): ")
    if edit_msg:
        commit_message = edit_commit_message(commit_message)
        print("\n" + SEP)
        print("                 UPDATED COMMIT MESSAGE")
        print(SEP + "\n")
        print(commit_message)
        print("\n" + SEP + "\n")

    if not non_interactive and not ask_yes_no("Commit with this message? (y/n): "):
        print("\nCommit cancelled.\n")
        return 0

    # README update (only if --update-readme or interactive and user says yes)
    do_readme = args.update_readme
    if not non_interactive and not do_readme:
        print()
        do_readme = ask_yes_no("Update README? (y/n): ")
    if do_readme:
        print("\nUpdating README...")
        ensure_readme(repo, commit_message, diff_for_ai, ai)
        run_git(repo, "add", "README.md", check=False)
        print("✅ README updated.\n")
    elif not non_interactive:
        print("\nSkipping README update.\n")

    # Commit
    print("Committing changes...")
    try:
        commit_changes(repo, commit_message)
        print("✅ Changes committed.\n")
    except subprocess.CalledProcessError as e:
        print("\n❌ ERROR: git commit failed\n", file=sys.stderr)
        stderr = (e.stderr or "").strip()
        if stderr:
            print(stderr + "\n", file=sys.stderr)
        if e.stdout and not stderr:
            print((e.stdout or "").strip() + "\n", file=sys.stderr)
        return 1

    if args.slack:
        try:
            sha = run_git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
            branch = current_branch(repo)

            files_in_commit = run_git(repo, "show", "--name-only", "--pretty=", "HEAD").stdout.splitlines()
            files_in_commit = [f.strip() for f in files_in_commit if f.strip()]

            slack_text = ai.generate_slack_update(
                repo_name=repo.name,
                branch=branch,
                commit_sha=sha,
                commit_message=commit_message,
                staged_files=files_in_commit,
                diff_summary=diff_for_ai[:8000],
            )
            send_slack_notification(slack_text)
            print("✅ Slack notification sent.\n")
        except Exception as e:
            print(f"⚠️  Slack notify failed: {e}", file=sys.stderr)


    if args.no_push:
        print("Skipping push (--no-push).\n")
    else:
        branch = current_branch(repo)
        upstream = get_push_target(repo)
        target = upstream if upstream else f"origin/{branch}"
        print(f"Pushing to {target}...")
        try:
            push_changes(repo, branch)
            print("✅ Changes pushed to remote.\n")
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or str(e)).strip()
            print(f"⚠️  WARNING: Push failed: {err}")
            print("(Commit was successful, but push failed)\n")

    if args.slack:
        send_slack_notification(commit_message)

    print(SEP)
    print("                        SUCCESS")
    print(SEP)
    print("\n✅ All changes have been committed successfully.\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
