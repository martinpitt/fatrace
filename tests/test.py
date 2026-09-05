import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path

TESTDIR = Path(__file__).parent.resolve()
ROOTDIR = TESTDIR.parent.resolve()

exe = subprocess.check_call

# check if root fs is btrfs
root_is_btrfs = subprocess.check_output(["findmnt", "--noheadings", "--output=FSTYPE", "/"]).strip() == b"btrfs"


def slow_exe(argv: list[str], **kwargs) -> None:
    """Run a command with tests/slow-exit.so

    Use this for test commands under fatrace, not for setup.
    """
    env = os.environ.copy()
    env["LD_PRELOAD"] = str(TESTDIR / "slow-exit.so")
    exe(argv, env=env, **kwargs)


def which(cmd: str) -> str:
    w = shutil.which(cmd)
    assert w
    return str(Path(w).resolve())


def retry_unmount(path: str) -> None:
    for _ in range(5):
        try:
            subprocess.call(["umount", path])
            break
        except subprocess.CalledProcessError as e:
            print(f"Retrying umount {path}: {e}")
            time.sleep(0.5)
    else:
        raise RuntimeError(f"Failed to unmount {path}")


class FatraceRunner:
    """Run fatrace with the given arguments in the background."""

    def __init__(self, args: list[str], json_output: bool = True):
        # we want to support multiple parallel FatraceRunners, so create our own private log dir
        self.log_dir = tempfile.TemporaryDirectory()
        self.output_file = os.path.join(self.log_dir.name, "fatrace.log")
        self.log_content: str | None = None

        fatrace_bin = "fatrace" if os.getenv("FATRACE_INSTALLED_TEST") else str(ROOTDIR / "fatrace")
        argv = [fatrace_bin, "-o", str(self.output_file)]
        if json_output:
            argv.append("--json")
        self.process = subprocess.Popen(argv + args)
        # wait until fatrace starts
        while not os.path.exists(self.output_file):
            time.sleep(0.1)

    def finish(self) -> None:
        """Wait for fatrace to finish and read the log content."""

        # fallback timeout; tests should use -s
        self.process.wait(timeout=10)
        with open(self.output_file, 'r') as f:
            self.log_content = f.read()
        self.log_dir.cleanup()

    def has_json(self, condition_func: Callable[[dict], bool]) -> bool:
        """Check if any JSON line matches the condition function."""

        assert self.log_content, "Need to call run() first"

        for line in self.log_content.strip().split('\n'):
            if not line:
                continue
            entry = json.loads(line)
            try:
                if condition_func(entry):
                    return True
            except KeyError:
                # Ignore entries that do not match the expected structure
                pass
        return False

    def assert_json(self, condition_func: Callable[[dict], bool]) -> None:
        if self.has_json(condition_func):
            return
        raise AssertionError("No JSON entry matched condition\n"
                             "---- Log content ----\n"
                             f"{self.log_content}\n"
                             "-----------------")

    def assert_not_json(self, condition_func: Callable[[dict], bool]) -> None:
        if not self.has_json(condition_func):
            return
        raise AssertionError("At least one JSON entry matched condition\n"
                             "---- Log content ----\n"
                             f"{self.log_content}\n"
                             "-----------------")

class FatraceTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        self.tmp_path = Path(self.tmp_dir.name)

        # isolated mount, so that --current-mount is shielded from other actions in the OS,
        # in particular writing our log file
        exe(["mount", "-t", "tmpfs", "-o", "size=250M", "tmpfs", str(self.tmp_path)])
        self.addCleanup(retry_unmount, str(self.tmp_path))
        # change away from mount to avoid EBUSY
        self.addCleanup(os.chdir, TESTDIR)

        os.chdir(self.tmp_path)

    def test_text_output(self):
        """Text format output

        Details covered in tests/test-event.c; only check that it works at all.
        """
        f = FatraceRunner(["--current-mount", "-s", "2"], json_output=False)

        test_file = self.tmp_path / "test.txt"
        slow_exe(["touch", str(test_file)])

        f.finish()
        assert f.log_content
        self.assertRegex(f.log_content,
                         re.compile(rf"^touch\(\d+\): C?W?O\s+{re.escape(str(test_file))}$", re.MULTILINE))

    def test_currentmount(self):
        f = FatraceRunner(["--current-mount", "-s", "2"])

        # Create/write/remove a file
        test_file = self.tmp_path / "test.txt"
        slow_exe(["touch", str(test_file)])
        test_file_stat = test_file.stat()
        slow_exe(["bash", "-c", f"echo $$ > '{test_file}'"])
        bash_pid = int(test_file.read_text())
        slow_exe(["head", str(test_file)], stdout=subprocess.DEVNULL)
        slow_exe(["rm", str(test_file)])

        # file name which is not valid UTF-8
        bad_file = self.tmp_path / f"bad-{chr(1)}.txt"
        slow_exe(["touch", str(bad_file)])

        # moving within same directory
        slow_exe(["touch", str(test_file)])
        test_file_2 = self.tmp_path / "test.txt.2"
        slow_exe(["mv", str(test_file), str(test_file_2)])

        # Create destination directory and move file there
        dest_dir = self.tmp_path / "dest"
        slow_exe(["mkdir", str(dest_dir)])
        dest_file = dest_dir / "test.txt.2"
        slow_exe(["mv", str(test_file_2), str(dest_file)])
        slow_exe(["rm", str(dest_file)])
        slow_exe(["rmdir", str(dest_dir)])

        # Test robustness against ELOOP
        link_file = self.tmp_path / "link"
        slow_exe(["ln", "-s", "nothing", str(link_file)])
        slow_exe(["rm", str(link_file)])

        f.finish()

        cwd = str(self.tmp_path)
        test_file_str = str(test_file)

        # file creation
        f.assert_json(lambda e: e["comm"] == "touch" and e["path"] == test_file_str and "O" in e["types"])
        f.assert_json(lambda e: e["comm"] == "touch" and e["path"] == test_file_str and "W" in e["types"])
        f.assert_json(lambda e: e["comm"] == "bash" and e["pid"] == bash_pid and
                      e["path"] == test_file_str and "W" in e["types"])

        # device and inode
        f.assert_json(lambda e: (
            e["comm"] == "touch" and
            e["path"] == test_file_str and
            e["device"] == {"major": os.major(test_file_stat.st_dev), "minor": os.minor(test_file_stat.st_dev)} and
            e["inode"] == test_file_stat.st_ino
        ))

        # non-UTF-8 paths have path_raw instead of path; details are covered in tests/test-event.c
        f.assert_json(lambda e: e["comm"] == "touch" and "path" not in e and
                      e["path_raw"] == list(str(bad_file).encode()))

        # file reading
        f.assert_json(lambda e: e["comm"] == "head" and e["path"] == test_file_str and "R" in e["types"])

        # file deletion
        f.assert_json(lambda e: e["comm"] == "rm" and e["path"] == cwd and e["types"] == "D")

        # directory creation
        f.assert_json(lambda e: e["comm"] == "touch" and e["path"] == cwd and e["types"] == "+")
        f.assert_json(lambda e: e["comm"] == "mkdir" and e["path"] == cwd and e["types"] == "+")

        # file renaming (can be one or two events)
        f.assert_json(lambda e: e["comm"] == "mv" and e["path"] == cwd and ">" in e["types"])

        # file moving between directories
        f.assert_json(lambda e: e["comm"] == "mv" and e["path"] == cwd and e["types"] == "<")
        f.assert_json(lambda e: e["comm"] == "mv" and e["path"] == str(dest_dir) and e["types"] == ">")

        # ELOOP symlink operations
        f.assert_json(lambda e: e["comm"] == "ln" and e["path"] == cwd and e["types"] == "+")

    def test_command(self):
        # command name that exceeds TASK_COMM_LEN (16 chars)
        long_cmd = self.tmp_path / "VeryLongTouchCommand"
        # Use our own simple-touch binary instead of /usr/bin/touch, to work with both
        # GNU coreutils (standalone binaries) and Rust coreutils (multi-call binary
        # that determines the utility based on argv[0])
        exe(["cp", str(TESTDIR / "simple-touch"), str(long_cmd)])

        f = FatraceRunner(["--current-mount", "--command", "VeryLongTouchCommand", "-s", "2"])

        # Create files with different programs
        slow_exe([str(long_cmd), str(self.tmp_path / "includeme")])
        slow_exe(["dd", "if=/dev/zero", f"of={self.tmp_path}/notme", "bs=1", "count=1", "status=none"])

        f.finish()

        # Should find the truncated command name (first 15 chars per TASK_COMM_LEN-1),
        # but not dd nor the file it created
        f.assert_json(lambda e: e["comm"] == "VeryLongTouchCo" and "W" in e["types"] and
                      e["path"] == str(self.tmp_path / "includeme"))
        f.assert_not_json(lambda e: e.get("comm") == "dd")
        f.assert_not_json(lambda e: "notme" in e.get("path", ""))

    def test_btrfs(self):
        if not shutil.which("mkfs.btrfs"):
            self.skipTest("mkfs.btrfs not installed")

        # Create btrfs filesystem
        image_file = self.tmp_path / "btrfs.img"
        mount_dir = self.tmp_path / "mount"

        exe(["dd", "if=/dev/zero", f"of={image_file}", "bs=1M", "count=200", "status=none"])
        exe(["mkfs.btrfs", "--quiet", str(image_file)])
        mount_dir.mkdir()
        exe(["mount", "-o", "loop", str(image_file), str(mount_dir)])
        self.addCleanup(retry_unmount, str(mount_dir))
        # Change away from mount point
        self.addCleanup(os.chdir, self.tmp_path)

        # Create subvolume
        os.chdir(mount_dir)
        exe(["btrfs", "subvolume", "create", str(mount_dir / "subv1")])

        # create initial file
        world_file = mount_dir / "world.txt"
        slow_exe(["bash", "-c", f"echo hello > '{world_file}'"])

        # The event types are covered by test_currentmount; this is about resolving paths
        # through the fsid → mount fd map, in particular on subvolumes (issue #3)
        f = FatraceRunner(["--current-mount", "-s", "2"])

        # Read existing file
        slow_exe(["head", str(world_file)], stdout=subprocess.DEVNULL)

        # Create/remove file
        test_file = mount_dir / "test.txt"
        slow_exe(["touch", str(test_file)])
        slow_exe(["rm", str(test_file)])

        # Create file on subvolume
        subvol_file = mount_dir / "subv1" / "sub.txt"
        slow_exe(["touch", str(subvol_file)])

        f.finish()
        mount_str = str(mount_dir)

        f.assert_json(lambda e: e["comm"] == "head" and "R" in e["types"] and e["path"] == str(world_file))
        f.assert_json(lambda e: e["comm"] == "touch" and e["types"] == "+" and e["path"] == mount_str)
        f.assert_json(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == str(test_file))
        f.assert_json(lambda e: e["comm"] == "rm" and e["types"] == "D" and e["path"] == mount_str)
        f.assert_json(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == str(subvol_file))

    def test_exe_parents(self):
        f = FatraceRunner(["--current-mount", "-s", "2", "--parents", "--exe"])

        # Create complex parent chain: touch → bash → python3 → test
        test_file = self.tmp_path / "file.tmp"
        bash_pid_file = self.tmp_path / "bash.pid"
        python_pid_file = self.tmp_path / "python.pid"

        python_script = f'''
import os, subprocess
subprocess.run(["bash", "-c", "touch {test_file}; echo $$ > {bash_pid_file}"])
with open("{python_pid_file}", "w") as f: f.write(f"{{os.getpid()}}\\n")
'''
        slow_exe([sys.executable, "-c", python_script])

        f.finish()

        # Read process information
        bash_pid = int(bash_pid_file.read_text().strip())
        python_pid = int(python_pid_file.read_text().strip())
        test_pid = os.getpid()

        # Get executable paths
        touch_exe = which("touch")
        bash_exe = which("bash")
        python_exe = which("python3")
        test_exe = Path("/proc/self/exe").resolve()
        init_comm = Path("/proc/1/comm").read_text().strip()
        init_exe = Path("/proc/1/exe").resolve()

        f.assert_json(lambda e: (
            e["comm"] == "touch" and
            e["path"] == str(test_file) and
            e["exe"] == str(touch_exe) and
            len(e["parents"]) >= 4 and
            e["parents"][0] == {"pid": bash_pid, "comm": "bash", "exe": str(bash_exe)} and
            e["parents"][1] == {"pid": python_pid, "comm": "python3", "exe": str(python_exe)} and
            e["parents"][2] == {"pid": test_pid, "comm": "python3", "exe": str(test_exe)} and
            e["parents"][-1] == {"pid": 1, "comm": init_comm, "exe": str(init_exe)}
        ))

    def test_user(self):
        nobody_user = pwd.getpwnam('nobody')
        nobody_uid = nobody_user.pw_uid
        nobody_gid = nobody_user.pw_gid

        test_file = self.tmp_path / "testfile.txt"
        test_file.write_text("test content")

        # Test user tracking functionality
        f = FatraceRunner(["--current-mount", "--user", "-s", "4"])

        def slow_exe_nobody(argv: list[str], **kwargs) -> None:
            exe(["runuser", "-u", "nobody",
                 "env", "LD_PRELOAD=" + str(TESTDIR / "slow-exit.so")] + argv,
                **kwargs)

        # read test file as root
        slow_exe(["head", str(test_file)], stdout=subprocess.DEVNULL)

        # Create a world-writable directory for user operations
        user_tmp = self.tmp_path / "user_tmp"
        user_tmp.mkdir()
        user_tmp.chmod(0o1777)

        # Create a file as user 'nobody'
        test_file_user = user_tmp / "testnobody.txt"
        slow_exe_nobody(["touch", str(test_file_user)])

        f.finish()

        f.assert_json(lambda e: (
            e["comm"] == "head" and
            e["uid"] == 0 and
            e["gid"] == 0 and
            "R" in e["types"] and
            e["path"] == str(test_file)
        ))

        f.assert_json(lambda e: (
            e["comm"] == "touch" and
            e["uid"] == nobody_uid and
            e["gid"] == nobody_gid and
            "W" in e["types"] and
            e["path"] == str(test_file_user)
        ))

    def test_dir(self):
        yes1 = str(self.tmp_path / "yes-1")
        yes2 = str(self.tmp_path / "yes-2")
        no1 = str(self.tmp_path / "no-1")

        exe(["mkdir", yes1])
        exe(["mkdir", yes2])
        exe(["mkdir", no1])

        # both ways of specifying directories
        f_opts = FatraceRunner(["-s", "3", "-d", yes1, f"--dir={yes2}"])
        f_args = FatraceRunner(["-s", "3", "--", yes1, yes2])

        slow_exe(["mkdir", f"{yes1}/subA"])
        slow_exe(["mkdir", f"{no1}/subB"])

        slow_exe(["touch", f"{yes1}/yesC"])
        slow_exe(["touch", f"{yes1}/subA/noD"])
        slow_exe(["touch", f"{yes2}/yesE"])
        slow_exe(["touch", f"{no1}/noF"])
        slow_exe(["touch", f"{no1}/subB/noG"])

        slow_exe(["mv", yes1, yes2])
        new_yes1 = str(self.tmp_path / "yes-2" / "yes-1")
        slow_exe(["mv", no1, yes2])
        new_no1 = str(self.tmp_path / "yes-2" / "no-1")

        slow_exe(["touch", f"{new_yes1}/yesH"])
        slow_exe(["touch", f"{new_yes1}/subA/noI"])
        slow_exe(["touch", f"{new_no1}/noJ"])
        slow_exe(["touch", f"{new_no1}/subB/noK"])

        def mkdir_in(path: str) -> Callable[[dict], bool]:
            return lambda e: e["comm"] == "mkdir" and e["types"] == "+" and e["path"] == path

        def touched(path: str) -> Callable[[dict], bool]:
            return lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == path

        # for unwatched paths, no event of any kind may appear; .get() as has_json() treats
        # a KeyError as "no match", which would make this pass for events without a path
        def on_path(path: str) -> Callable[[dict], bool]:
            return lambda e: e.get("path") == path

        for f in (f_opts, f_args):
            f.finish()

            f.assert_json    (mkdir_in(yes1))
            f.assert_not_json(on_path(no1))
            f.assert_json    (touched(f"{yes1}/yesC"))
            f.assert_not_json(on_path(f"{yes1}/subA/noD"))
            f.assert_json    (touched(f"{yes2}/yesE"))
            f.assert_not_json(on_path(f"{no1}/noF"))
            f.assert_not_json(on_path(f"{no1}/subB/noG"))
            f.assert_json    (touched(f"{new_yes1}/yesH"))
            f.assert_not_json(on_path(f"{new_yes1}/subA/noI"))
            f.assert_not_json(on_path(f"{new_no1}/noJ"))
            f.assert_not_json(on_path(f"{new_no1}/subB/noK"))

    @unittest.skipIf("container" in os.environ, "Not supported in container environment")
    @unittest.skipIf(os.path.exists("/sysroot/ostree"), "Test does not work on OSTree")
    @unittest.skipIf(root_is_btrfs, "FANOTIFY does not work on btrfs, https://github.com/martinpitt/fatrace/issues/3")
    def test_all_mounts(self):
        f = FatraceRunner(["-s", "2"])

        # read a system file
        slow_exe(["head", "/etc/passwd"], stdout=subprocess.DEVNULL)

        # create and remove a file
        test_file = Path("/tmp/fatrace-test.txt")
        slow_exe(["touch", str(test_file)])
        slow_exe(["rm", str(test_file)])

        f.finish()

        # events on different mounts resolve to paths
        head_binary = which("head")
        f.assert_json(lambda e: "R" in e["types"] and e["path"] == head_binary)
        f.assert_json(lambda e: "R" in e["types"] and e["path"] == "/etc/passwd")
        f.assert_json(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == str(test_file))
        f.assert_json(lambda e: e["comm"] == "touch" and e["types"] == "+" and e["path"] == "/tmp")
        f.assert_json(lambda e: e["comm"] == "rm" and e["types"] == "D" and e["path"] == "/tmp")
