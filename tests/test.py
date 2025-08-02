#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

MYDIR = Path(__file__).parent.parent.resolve()


class FatraceRunner:
    def __init__(self, args: list[str], output_dir: Path):
        self.output_file = output_dir / "fatrace.log"
        self.log_content: str | None = None
        self.process = subprocess.Popen([str(MYDIR / "fatrace"), "-o", str(self.output_file)] + args)
        time.sleep(1)  # Give fatrace time to initialize

    def finish(self) -> None:
        """Wait for fatrace to finish and read the log content."""
        # fallback timeout; tests should use -s
        self.process.wait(timeout=10)
        with open(self.output_file, 'r') as f:
            self.log_content = f.read()

    def assert_log(self, pattern: str):
        assert self.log_content, "Need to call run() first"
        """Check if a regex pattern exists in the log content."""
        if not re.search(pattern, self.log_content, re.MULTILINE):
            raise AssertionError(f"""Pattern not found in log: {pattern}
---- Log content ----
{self.log_content}
-----------------""")


class FatraceTests(unittest.TestCase):
    """Test cases for fatrace functionality."""

    def setUp(self):
        """Set up test environment."""
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        self.tmp_path = Path(self.tmp_dir.name)
        os.chdir(self.tmp_path)

    def test_currentmount(self):
        f = FatraceRunner(["--current-mount", "-s", "2"], self.tmp_path)

        # Create a file
        test_file = self.tmp_path / "test.txt"
        subprocess.check_call(["touch", str(test_file)])
        subprocess.check_call(["bash", "-c", f"echo hello > '{test_file}'"])
        subprocess.check_call(["head", str(test_file)], stdout=subprocess.DEVNULL)
        subprocess.check_call(["rm", str(test_file)])

        # moving within same directory
        subprocess.check_call(["touch", str(test_file)])
        test_file_2 = self.tmp_path / "test.txt.2"
        subprocess.check_call(["mv", str(test_file), str(test_file_2)])

        # Create destination directory and move file there
        dest_dir = self.tmp_path / "dest"
        subprocess.check_call(["mkdir", str(dest_dir)])
        dest_file = dest_dir / "test.txt.2"
        subprocess.check_call(["mv", str(test_file_2), str(dest_file)])
        subprocess.check_call(["rm", str(dest_file)])
        subprocess.check_call(["rmdir", str(dest_dir)])

        # Test robustness against ELOOP
        link_file = self.tmp_path / "link"
        subprocess.check_call(["ln", "-s", "nothing", str(link_file)])
        try:
            os.open(str(link_file), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            pass  # Expected to fail
        subprocess.check_call(["rm", str(link_file)])

        f.finish()

        if not f.log_content:
            self.fail("No output captured from fatrace")

        # Convert paths to strings for pattern matching
        cwd = str(self.tmp_path)
        test_file_str = str(test_file)

        # file creation
        f.assert_log(rf"^touch.*\sC?W?O\s+{re.escape(test_file_str)}")
        f.assert_log(rf"^touch.*\sC?WO?\s+{re.escape(test_file_str)}")
        f.assert_log(rf"^bash.*\sC?WO?\s+{re.escape(test_file_str)}")

        # file reading
        f.assert_log(rf"^head.*\sRC?O?\s+{re.escape(test_file_str)}")

        # file deletion
        f.assert_log(rf"^rm.*:\s+D\s+{re.escape(cwd)}$")

        # Check directory creation
        f.assert_log(rf"^touch.*:\s+\+\s+{re.escape(cwd)}$")
        f.assert_log(rf"^mkdir.*:\s+\+\s+{re.escape(cwd)}$")

        # Check file renaming (can be one or two events)
        f.assert_log(rf"^mv.*:\s+<>?\s+{re.escape(cwd)}")
        f.assert_log(rf"^mv.*:\s+<?>\s+{re.escape(cwd)}")

        # Check file moving between directories
        f.assert_log(rf"^mv.*:\s+<\s+{re.escape(cwd)}$")
        f.assert_log(rf"^mv.*:\s+>\s+{re.escape(cwd)}/dest$")

        # Check ELOOP symlink operations
        f.assert_log(rf"^ln.*:\s+\+\s+{re.escape(cwd)}$")
        f.assert_log(rf"^rm.*:\s+D\s+{re.escape(cwd)}$")
