"""The harness itself: what `run_script` reports about the files that a run leaves.

A test that asserts `run.tmp_files == []` or `run.home_files == []` proves nothing if the
harness never lists a file. This is the positive control.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

LEAVES_FILES = """#!/usr/bin/env bash
set -euo pipefail
: > "$HOME/.dot-file"
: > in-the-working-directory
sub="$(mktemp -d "$HOME/sub-XXXXXX")"
: > "$sub/in-a-subdirectory"
: > "$TMPDIR/in-tmpdir"
gcloud version
"""


class LeftFiles(unittest.TestCase):

    def test_the_harness_lists_each_file_that_a_run_leaves(self):
        with tempfile.TemporaryDirectory(prefix="deteng-harness-") as folder:
            script = os.path.join(folder, "leaves_files.sh")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(LEAVES_FILES)
            run = livetest.run_script(script, files=["given-by-the-test"])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [["gcloud", "version"]], run.text)
        self.assertEqual(run.tmp_files, ["in-tmpdir"], run.text)
        names = [os.path.basename(path) for path in run.home_files]
        self.assertEqual(sorted(names), [".dot-file", "in-a-subdirectory", "in-the-working-directory"],
                         run.home_files)
        self.assertTrue(any(os.sep in path for path in run.home_files), run.home_files)

    def test_a_run_that_leaves_no_file_has_two_empty_lists(self):
        run = livetest.run_script("atomics/tests/pipe_to_head.sh", "atomics/T1199/src/emulate_gcp_workforce.sh",
                                  "3", "a")
        self.assertEqual((run.tmp_files, run.home_files), ([], []), run.text)


if __name__ == "__main__":
    unittest.main()
