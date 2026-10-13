"""Synthetic temporary-repository tests; no model/EDA or historical result claims."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_paper_snapshot.py"
SPEC = importlib.util.spec_from_file_location("paper_snapshot", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class PaperSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self.frozen = self.root / "paper/iscas2027"
        self.frozen.mkdir(parents=True)
        self.source = self.frozen / "source.py"
        self.source.write_bytes(b"raise RuntimeError('never execute captured source')\n")
        (self.frozen / "manifest.json").write_text('{"fixture": true}\n')
        (self.root / ".gitignore").write_text("*.ignored\n__pycache__/\n.DS_Store\n")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Snapshot Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()
        self.git("tag", guard.BASE_TAG)
        self.pin = patch.object(guard, "BASE_COMMIT", self.commit)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def git(self, *args):
        # Keep authoring synthetic commits independent of user hooks/config.
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.run(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgSign=false", "-C", str(self.root), *args],
            env=env, check=True, capture_output=True, text=True, timeout=30,
        ).stdout

    def assertFailure(self, reason):
        result = guard.check_snapshot(self.root)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(reason in error for error in result["errors"]), result)

    def test_pristine_snapshot_passes_without_executing_source(self):
        report = guard.check_snapshot(self.root)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["files_checked"], 2)
        self.assertEqual(report["base_commit"], self.commit)

    def test_modified_source_and_manifest_cannot_relock_snapshot(self):
        self.source.write_text("print('changed')\n")
        (self.frozen / "manifest.json").write_text('{"new_hash": "replacement"}\n')
        self.git("add", "paper")
        self.assertFailure("index differs")
        self.assertFailure("bytes or executable mode changed")

    def test_unstaged_tamper_is_detected(self):
        self.source.write_bytes(b"changed\r\n")
        self.assertFailure("bytes or executable mode changed")

    def test_deleted_file_is_detected(self):
        self.source.unlink()
        self.assertFailure("missing published file")

    def test_index_deletion_with_file_retained_is_detected(self):
        self.git("rm", "--cached", "paper/iscas2027/source.py")
        self.assertTrue(self.source.is_file())
        self.assertFailure("index differs")

    def test_untracked_ignored_and_staged_additions_are_detected(self):
        added = self.frozen / "new.ignored"
        added.write_text("meaningful source even when ignored\n")
        self.assertFailure("unexpected file")
        self.git("add", "-f", "paper/iscas2027/new.ignored")
        self.assertFailure("index differs")

    def test_incidental_files_are_tolerated_but_source_in_cache_is_not(self):
        cache = self.frozen / "__pycache__"
        cache.mkdir()
        (cache / "source.cpython-312.pyc").write_bytes(b"incidental bytecode")
        (self.frozen / ".DS_Store").write_bytes(b"incidental OS metadata")
        self.assertEqual(guard.check_snapshot(self.root)["status"], "PASS")
        (cache / "new_source.py").write_text("meaningful source\n")
        self.assertFailure("unexpected file")

    def test_tracked_incidental_file_is_an_addition(self):
        (self.frozen / ".DS_Store").write_bytes(b"metadata")
        self.git("add", "-f", "paper/iscas2027/.DS_Store")
        self.assertFailure("index differs")

    def test_file_symlink_is_rejected_even_with_identical_target_bytes(self):
        outside = self.root / "copy.py"
        outside.write_bytes(self.source.read_bytes())
        self.source.unlink()
        self.source.symlink_to(outside)
        self.assertFailure("symlink is forbidden")

    def test_directory_symlink_escape_and_incidental_symlink_are_rejected(self):
        (self.frozen / "escape").symlink_to(self.root, target_is_directory=True)
        (self.frozen / ".DS_Store").symlink_to(self.source)
        self.assertFailure("symlink is forbidden")

    def test_parent_directory_symlink_is_rejected(self):
        (self.root / "paper").rename(self.root / "external-paper")
        (self.root / "paper").symlink_to(self.root / "external-paper", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "frozen directory"):
            guard.check_snapshot(self.root)

    def test_missing_commit_and_tag_fail_closed(self):
        with patch.object(guard, "BASE_COMMIT", "0" * 40):
            with self.assertRaisesRegex(ValueError, "local Git read failed"):
                guard.check_snapshot(self.root)
        self.git("tag", "-d", guard.BASE_TAG)
        with self.assertRaisesRegex(ValueError, "local Git read failed"):
            guard.check_snapshot(self.root)

    def test_moved_tag_cannot_redefine_published_commit(self):
        (self.root / "development.txt").write_text("outside frozen tree\n")
        self.git("add", "development.txt")
        self.git("-c", "user.name=Snapshot Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "development")
        self.assertEqual(guard.check_snapshot(self.root)["status"], "PASS")
        self.git("tag", "-f", guard.BASE_TAG)
        with self.assertRaisesRegex(ValueError, "exact pinned commit"):
            guard.check_snapshot(self.root)

    def test_rejects_path_traversal_in_tree_metadata(self):
        for unsafe in ("paper/iscas2027/../../outside", "/paper/iscas2027/source.py"):
            with self.subTest(path=unsafe), self.assertRaisesRegex(ValueError, "unsafe path"):
                guard.read_entries(f"100644 blob {'a' * 40}\t{unsafe}\0".encode())

    def test_executable_mode_change_is_detected(self):
        self.source.chmod(0o755)
        self.assertFailure("bytes or executable mode changed")


if __name__ == "__main__":
    unittest.main()
