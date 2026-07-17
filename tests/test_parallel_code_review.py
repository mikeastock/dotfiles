from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
PROJECT_DIR = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROJECT_DIR / "skills/parallel-code-review/scripts/run_parallel_reviews.py"
SPEC = importlib.util.spec_from_file_location("parallel_code_review", RUNNER_PATH)
assert SPEC and SPEC.loader
parallel_code_review = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = parallel_code_review
SPEC.loader.exec_module(parallel_code_review)
BUILD_SPEC = importlib.util.spec_from_file_location("dotfiles_build", PROJECT_DIR / "scripts/build.py")
assert BUILD_SPEC and BUILD_SPEC.loader
dotfiles_build = importlib.util.module_from_spec(BUILD_SPEC)
sys.modules[BUILD_SPEC.name] = dotfiles_build
BUILD_SPEC.loader.exec_module(dotfiles_build)


def git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


class ParallelCodeReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "--quiet", "--initial-branch=main")
        git(self.repository, "config", "user.email", "tests@example.com")
        git(self.repository, "config", "user.name", "Tests")
        (self.repository / "review.txt").write_text("base\n")
        git(self.repository, "add", "review.txt")
        git(self.repository, "commit", "--quiet", "-m", "base")
        self.base_sha = git(self.repository, "rev-parse", "HEAD")
        (self.repository / "review.txt").write_text("base\nhead\n")
        git(self.repository, "commit", "--quiet", "-am", "head")
        self.head_sha = git(self.repository, "rev-parse", "HEAD")
        self.brief = self.root / "brief.md"
        self.brief.write_text(
            "Goal: validate the parallel reviewer.\n"
            "Context: test fixture repository.\n"
            "Constraints: review only.\n"
            "Verification: focused tests.\n"
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def args(self, **overrides: object) -> argparse.Namespace:
        values = {
            "repo": str(self.repository),
            "base": "HEAD~1",
            "against_main": False,
            "pr": None,
            "head": None,
            "allow_dirty": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_resolves_and_pins_explicit_fixed_point(self) -> None:
        scope = parallel_code_review.resolve_scope(self.args())

        self.assertEqual(scope.fixed_sha, self.base_sha)
        self.assertEqual(scope.merge_base_sha, self.base_sha)
        self.assertEqual(scope.head_sha, self.head_sha)
        self.assertEqual(scope.changed_files, 1)

    def test_rejects_invalid_and_empty_fixed_points(self) -> None:
        with self.assertRaisesRegex(parallel_code_review.ReviewError, "does not resolve"):
            parallel_code_review.resolve_scope(self.args(base="missing-ref"))
        with self.assertRaisesRegex(parallel_code_review.ReviewError, "scope is empty"):
            parallel_code_review.resolve_scope(self.args(base="HEAD"))

    def test_dirty_tree_requires_explicit_exclusion(self) -> None:
        (self.repository / "untracked.txt").write_text("not reviewed\n")

        with self.assertRaisesRegex(parallel_code_review.ReviewError, "--allow-dirty"):
            parallel_code_review.resolve_scope(self.args())

        scope = parallel_code_review.resolve_scope(self.args(allow_dirty=True))
        self.assertEqual(scope.dirty_entries, 1)
        self.assertEqual(scope.head_sha, self.head_sha)

    def test_explicit_main_comparison_pins_remote_default(self) -> None:
        git(self.repository, "update-ref", "refs/remotes/origin/main", self.base_sha)
        git(self.repository, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

        scope = parallel_code_review.resolve_scope(
            self.args(base=None, against_main=True)
        )

        self.assertEqual(scope.fixed_point, "origin/main")
        self.assertEqual(scope.fixed_sha, self.base_sha)

    def test_safe_dry_run_validates_without_creating_clones(self) -> None:
        output = self.root / "dry-run"

        exit_code = parallel_code_review.main(
            [
                "--repo",
                str(self.repository),
                "--base",
                "HEAD~1",
                "--run-dir",
                str(output),
                "--brief-file",
                str(self.brief),
                "--dry-run",
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue((output / "scope.json").is_file())
        self.assertTrue((output / "dry-run.json").is_file())
        self.assertFalse((output / "clones").exists())

    def test_disposable_clone_pins_grok_base_and_disables_remote(self) -> None:
        scope = parallel_code_review.resolve_scope(self.args())
        clone = self.root / "reviewer-clone"

        parallel_code_review.prepare_clone(scope, clone)

        self.assertEqual(git(clone, "rev-parse", "HEAD"), self.head_sha)
        self.assertEqual(
            git(clone, "rev-parse", "refs/remotes/origin/main"),
            self.base_sha,
        )
        self.assertEqual(git(clone, "merge-base", "origin/main", "HEAD"), self.base_sha)
        self.assertEqual(git(clone, "rev-parse", "main"), self.base_sha)
        self.assertEqual(git(clone, "remote", "get-url", "origin"), "disabled://parallel-code-review")
        self.assertFalse((clone / ".git/objects/info/alternates").exists())

    def test_disposable_clone_excludes_uncommitted_git_objects(self) -> None:
        secret = self.repository / "secret.txt"
        secret.write_text("uncommitted secret\n")
        git(self.repository, "add", "secret.txt")
        secret_blob = git(self.repository, "rev-parse", ":secret.txt")
        git(self.repository, "reset", "--quiet", "HEAD", "secret.txt")
        scope = parallel_code_review.resolve_scope(self.args(allow_dirty=True))
        clone = self.root / "isolated-clone"

        parallel_code_review.prepare_clone(scope, clone)

        leaked = subprocess.run(
            ["git", "-C", str(clone), "cat-file", "-e", secret_blob],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        self.assertNotEqual(leaked.returncode, 0)

    def test_failed_clone_preparation_removes_partial_clone(self) -> None:
        scope = parallel_code_review.resolve_scope(self.args())
        invalid_scope = parallel_code_review.dataclasses.replace(
            scope,
            head_sha="0" * 40,
        )
        clone = self.root / "partial-clone"

        with self.assertRaises(parallel_code_review.ReviewError):
            parallel_code_review.prepare_clone(invalid_scope, clone)

        self.assertFalse(clone.exists())

    def test_rejects_reused_output_directory(self) -> None:
        existing = self.root / "existing-run"
        existing.mkdir()

        with self.assertRaisesRegex(parallel_code_review.ReviewError, "already exists"):
            parallel_code_review.create_run_directory(str(existing))

    def test_build_metadata_stripping_removes_empty_block_across_blank_line(self) -> None:
        content = (
            "---\n"
            "name: fixture\n"
            "metadata:\n"
            "  agents: codex, pi\n"
            "  user-invocable-only: true\n"
            "\n"
            "description: fixture\n"
            "---\n"
        )

        stripped = dotfiles_build.strip_agents_from_frontmatter(content)

        self.assertNotIn("metadata:", stripped)
        self.assertIn("description: fixture", stripped)

    def process_task(
        self,
        name: str,
        delay: float,
        exit_code: int,
        registry: object,
        deadline: float,
    ):
        output = self.root / f"{name}.out"
        stderr = self.root / f"{name}.err"

        def task() -> Path:
            command = [
                sys.executable,
                "-c",
                f"import time; time.sleep({delay}); print('{name}'); raise SystemExit({exit_code})",
            ]
            code = parallel_code_review.run_process(
                command,
                cwd=self.root,
                stdout_path=output,
                stderr_path=stderr,
                deadline=deadline,
                registry=registry,
            )
            if code:
                raise parallel_code_review.ReviewError(f"fixture exited {code}")
            return output

        return task

    def test_reviewers_run_concurrently_and_report_partial_failure(self) -> None:
        registry = parallel_code_review.ProcessRegistry()
        deadline = time.monotonic() + 5
        tasks = {
            "fable": self.process_task("fable", 1.0, 0, registry, deadline),
            "grok": self.process_task("grok", 1.0, 7, registry, deadline),
            "thermo": self.process_task("thermo", 1.0, 0, registry, deadline),
        }

        started = time.monotonic()
        results = parallel_code_review.run_reviewers(tasks)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 2.5)
        self.assertEqual(results["fable"].status, "completed")
        self.assertEqual(results["grok"].status, "failed")
        self.assertEqual(results["thermo"].status, "completed")

        scope = parallel_code_review.resolve_scope(self.args())
        summary = parallel_code_review.write_summary(self.root, scope, results, [])
        summary_text = summary.read_text()
        self.assertIn("partial failure", summary_text)
        self.assertIn("Missing or failed reviewer output is not approval", summary_text)

    def test_timeout_kills_owned_process_group(self) -> None:
        registry = parallel_code_review.ProcessRegistry()
        marker = self.root / "late-child-output"
        output = self.root / "timeout.out"
        stderr = self.root / "timeout.err"
        child_code = f"import time, pathlib; time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('escaped')"
        parent_code = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "time.sleep(10)"
        )

        with self.assertRaises(parallel_code_review.ReviewTimeout):
            parallel_code_review.run_process(
                [sys.executable, "-c", parent_code],
                cwd=self.root,
                stdout_path=output,
                stderr_path=stderr,
                deadline=time.monotonic() + 0.15,
                registry=registry,
            )
        time.sleep(0.65)
        self.assertFalse(marker.exists())

    def test_setup_command_timeout_uses_owned_process_group(self) -> None:
        registry = parallel_code_review.ProcessRegistry()

        with self.assertRaises(parallel_code_review.ReviewTimeout):
            parallel_code_review.run_external(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=self.root,
                text=True,
                deadline=time.monotonic() + 0.15,
                registry=registry,
            )

    def test_successful_leader_cannot_leave_reviewer_descendants(self) -> None:
        registry = parallel_code_review.ProcessRegistry()
        marker = self.root / "orphan-output"
        output = self.root / "leader.out"
        stderr = self.root / "leader.err"
        child_code = f"import time, pathlib; time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('escaped')"
        parent_code = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}])"
        )

        code = parallel_code_review.run_process(
            [sys.executable, "-c", parent_code],
            cwd=self.root,
            stdout_path=output,
            stderr_path=stderr,
            deadline=time.monotonic() + 5,
            registry=registry,
        )

        self.assertEqual(code, 0)
        time.sleep(0.65)
        self.assertFalse(marker.exists())

    def test_cancellation_terminates_registered_process(self) -> None:
        registry = parallel_code_review.ProcessRegistry()
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            start_new_session=True,
        )
        registry.add(process, self.root)

        registry.terminate_all()

        self.assertTrue(registry.cancelled.is_set())
        self.assertIsNotNone(process.poll())

    def test_fable_requires_success_terminal_result_and_removes_raw_stream(self) -> None:
        output_dir = self.root / "fable"
        output_dir.mkdir()
        claude = self.root / "claude-fixture"
        claude.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"terminal_reason\":\"completed\",\"result\":\"premature success\"}'\n"
            "printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"error\",\"is_error\":true,\"terminal_reason\":\"failed\",\"result\":\"partial\"}'\n"
        )
        claude.chmod(0o755)
        scope = parallel_code_review.resolve_scope(self.args())

        with self.assertRaisesRegex(parallel_code_review.ReviewError, "no non-empty final result"):
            dependencies = parallel_code_review.Dependencies(
                claude=claude,
                pi=claude,
                grok_wrapper=claude,
                thermo_skill=self.brief,
            )
            parallel_code_review.run_fable(
                parallel_code_review.ReviewContext(
                    scope,
                    self.brief.read_text(),
                    dependencies,
                    parallel_code_review.ProcessRegistry(),
                ),
                self.repository,
                output_dir,
                time.monotonic() + 5,
            )

        self.assertFalse((output_dir / "stream.jsonl").exists())
        self.assertFalse((output_dir / "prompt.md").exists())
        self.assertTrue((output_dir / "result-diagnostic.json").is_file())

    def test_thermo_requires_final_plugin_owned_verdict(self) -> None:
        review = self.root / "thermo.md"
        skill = self.root / "thermo-skill.md"
        skill.write_text(
            "### Verdict\n\n"
            "**APPROVE** — Healthy.\n\n"
            "**RETHINK** — Blocked.\n\n"
            "**REFINE** — Improve.\n\n---\n"
        )
        review.write_text("\n")

        with self.assertRaisesRegex(parallel_code_review.ReviewError, "final plugin verdict"):
            parallel_code_review.validate_thermo_result(review, skill)
        self.assertTrue((self.root / "result-diagnostic.json").is_file())

        review.write_text("A finding.\n\n**REFINE** — Address the major issue.\n")
        parallel_code_review.validate_thermo_result(review, skill)

        review.write_text(
            "Quoted rubric:\n**APPROVE** — Example only.\n\n**RETHINK** — Actual verdict.\n"
        )
        with self.assertRaisesRegex(parallel_code_review.ReviewError, "exactly one"):
            parallel_code_review.validate_thermo_result(review, skill)

        review.write_text("**APPROVE** — \n")
        with self.assertRaisesRegex(parallel_code_review.ReviewError, "exactly one"):
            parallel_code_review.validate_thermo_result(review, skill)

    def test_grok_wait_error_invokes_canonical_stop(self) -> None:
        output_dir = self.root / "grok"
        output_dir.mkdir()
        wrapper = self.root / "grok-wrapper"
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"$1\" == start ]]; then\n"
            "  mkdir -p \"$4\"\n"
            "  printf '%s\\n' grok-review-fixture > \"$4/zmx-session\"\n"
            "elif [[ \"$1\" == wait ]]; then\n"
            "  exit 7\n"
            "elif [[ \"$1\" == stop ]]; then\n"
            "  printf '%s\\n' stopped > \"$2/stop-called\"\n"
            "fi\n"
        )
        wrapper.chmod(0o755)
        with self.assertRaisesRegex(parallel_code_review.ReviewError, "Grok wait exited 7"):
            scope = parallel_code_review.resolve_scope(self.args())
            dependencies = parallel_code_review.Dependencies(
                claude=wrapper,
                pi=wrapper,
                grok_wrapper=wrapper,
                thermo_skill=self.brief,
            )
            parallel_code_review.run_grok(
                parallel_code_review.ReviewContext(
                    scope,
                    self.brief.read_text(),
                    dependencies,
                    parallel_code_review.ProcessRegistry(),
                ),
                self.repository,
                output_dir,
                time.monotonic() + 5,
            )

        self.assertTrue((output_dir / "run/stop-called").is_file())

    def test_cleanup_removes_only_owned_clones(self) -> None:
        clone_one = self.root / "clones" / "one"
        clone_two = self.root / "clones" / "two"
        sibling = self.root / "keep"
        clone_one.mkdir(parents=True)
        clone_two.mkdir(parents=True)
        sibling.mkdir()

        errors = parallel_code_review.cleanup_clones(
            {"one": clone_one, "two": clone_two}
        )

        self.assertEqual(errors, [])
        self.assertFalse(clone_one.exists())
        self.assertFalse(clone_two.exists())
        self.assertTrue(sibling.exists())

    def test_missing_reviewer_result_is_never_complete(self) -> None:
        results = {
            name: parallel_code_review.ReviewResult(name, "completed", 0.1)
            for name in ("fable", "grok")
        }

        self.assertFalse(parallel_code_review.all_reviews_completed(results))

        invalid_results = parallel_code_review.run_reviewers(
            {"fable": lambda: self.root / "missing-review.md"}
        )
        self.assertEqual(invalid_results["fable"].status, "failed")

    def test_clone_setup_failure_produces_aggregate_failure_results(self) -> None:
        results = parallel_code_review.setup_failure_results(
            "grok",
            parallel_code_review.ReviewTimeout("clone timed out"),
        )
        scope = parallel_code_review.resolve_scope(self.args())
        summary = parallel_code_review.write_summary(self.root, scope, results, [])

        self.assertEqual(set(results), {"fable", "grok", "thermo"})
        self.assertEqual(results["grok"].status, "timed_out")
        self.assertEqual(results["fable"].status, "not_started")
        self.assertIn("Overall: **failed**", summary.read_text())

    def test_fable_uses_last_terminal_event(self) -> None:
        stream = self.root / "fable-stream.jsonl"
        output = self.root / "fable-review.md"
        stream.write_text(
            '["non-object event"]\n'
            '{"type":"result","subtype":"error","is_error":true,"result":"partial"}\n'
            '{"type":"result","subtype":"success","is_error":false,"terminal_reason":"completed","result":"final review"}\n'
        )

        parallel_code_review.parse_fable_result(stream, output)

        self.assertEqual(output.read_text(), "final review\n")

    def test_resolves_pr_metadata_and_requires_exact_local_head(self) -> None:
        fake_bin = self.root / "pr-bin"
        fake_bin.mkdir()
        gh = fake_bin / "gh"
        gh.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' '{{\"number\":42,\"headRefOid\":\"{self.head_sha}\",\"baseRefOid\":\"{self.base_sha}\",\"headRefName\":\"feature\",\"baseRefName\":\"main\"}}'\n"
        )
        gh.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{fake_bin}:{old_path}"
        try:
            scope = parallel_code_review.resolve_scope(
                self.args(base=None, pr="42")
            )
            self.assertEqual(scope.fixed_sha, self.base_sha)
            self.assertEqual(scope.head_sha, self.head_sha)

            git(self.repository, "checkout", "--quiet", "HEAD~1")
            with self.assertRaisesRegex(parallel_code_review.ReviewError, "does not match"):
                parallel_code_review.resolve_scope(self.args(base=None, pr="42"))
        finally:
            os.environ["PATH"] = old_path

    def test_non_dry_run_main_uses_real_adapter_contracts_and_cleans_clones(self) -> None:
        fake_bin = self.root / "review-bin"
        fake_bin.mkdir()
        claude = fake_bin / "claude"
        claude.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"terminal_reason\":\"completed\",\"result\":\"Fable review\"}'\n"
        )
        claude.chmod(0o755)
        pi = fake_bin / "pi"
        pi.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' 'Thermo review' '**APPROVE** — No structural regressions.'\n"
        )
        pi.chmod(0o755)
        test_home = self.root / "review-home"
        grok = test_home / ".agents/skills/grok-review/scripts/run_review.sh"
        grok.parent.mkdir(parents=True)
        grok.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ $1 == start ]]; then\n"
            "  mkdir -p \"$4\"\n"
            "  printf '%s\\n' 'Grok review' > \"$4/review.md\"\n"
            "fi\n"
        )
        grok.chmod(0o755)
        thermo_skill = test_home / ".agents/skills/thermo-nuclear-code-review/SKILL.md"
        thermo_skill.parent.mkdir(parents=True)
        thermo_skill.write_text(
            "---\nname: thermo\ndescription: fixture\n---\n"
            "### Verdict\n\n**APPROVE** — Healthy.\n\n---\n"
        )
        output = self.root / "full-run"
        overrides = {
            "HOME": str(test_home),
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
        }
        previous = {name: os.environ.get(name) for name in overrides}
        os.environ.update(overrides)
        try:
            exit_code = parallel_code_review.main(
                [
                    "--repo",
                    str(self.repository),
                    "--base",
                    "HEAD~1",
                    "--run-dir",
                    str(output),
                    "--brief-file",
                    str(self.brief),
                    "--timeout-seconds",
                    "5",
                ]
            )
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.assertEqual(exit_code, 0)
        self.assertIn("complete", (output / "summary.md").read_text())
        self.assertEqual(list((output / "clones").iterdir()), [])
        for reviewer in ("fable", "grok", "thermo"):
            self.assertTrue((output / "reviewers" / reviewer / "review.md").is_file())


if __name__ == "__main__":
    unittest.main()
