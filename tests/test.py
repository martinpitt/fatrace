#!/usr/bin/env python3
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import sys

from pathlib import Path
from typing import Callable

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

class FatraceRunnerBase:
    def __init__(self, args: list[str], convert_line = lambda x: x, convert_condition = lambda x: x):
        # we want to support multiple parallel FatraceRunners, so create our own private log dir
        self.convert_line = convert_line
        self.convert_condition = convert_condition
        self.log_dir = tempfile.TemporaryDirectory()
        self.output_file = os.path.join(self.log_dir.name, "fatrace.log")
        self.log_content: str | None = None
        self.finished: bool = False

        fatrace_bin = "fatrace" if os.getenv("FATRACE_INSTALLED_TEST") else str(ROOTDIR / "fatrace")
        self.process = subprocess.Popen([fatrace_bin, "-o", str(self.output_file), *args])
        # wait until fatrace starts
        while not os.path.exists(self.output_file):
            time.sleep(0.1)

    def has_log(self, condition) -> bool:
        """Check if any line matches the condition."""

        if not self.finished:
            # fallback timeout; tests should use -s
            self.process.wait(timeout=10)
            with open(self.output_file, 'r') as f:
                self.log_content = f.read()
            self.log_dir.cleanup()
            self.log_converted = [
                self.convert_line(line)
                for line in self.log_content.strip().split('\n')
                if line]
            self.finished = True

        condition_func = self.convert_condition(condition)
        for entry in self.log_converted:
            try:
                if condition_func(entry):
                    return True
            except KeyError:
                # Ignore entries that do not match the expected structure
                pass
        return False

    def assert_log(self, condition) -> None:
        if self.has_log(condition):
            return
        raise AssertionError("No entry matched condition\n"
                             "---- Log content ----\n"
                             f"{self.log_content}\n"
                             "-----------------")

    def assert_not_log(self, condition) -> None:
        if not self.has_log(condition):
            return
        raise AssertionError("At least one entry matched condition\n"
                             "---- Log content ----\n"
                             f"{self.log_content}\n"
                             "-----------------")

def FatraceRunnerText(*args: str):
    assert "--json" not in args
    return FatraceRunnerBase([*args], convert_condition = lambda regex: lambda line: bool(re.search(regex, line)))

def FatraceRunnerJson(*args: str):
    assert "--json" in args
    return FatraceRunnerBase([*args], convert_line = json.loads)

def parse_fatrace_text_line(line):
    result = {}
    remaining = line.strip()
    timestamp_match = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d{6}|\d+\.\d{6})\s+', remaining)
    if timestamp_match:
        result['timestamp'] = timestamp_match.group(1)
        remaining = remaining[timestamp_match.end():]
    proc_match = re.match(r'([^(]+)\((\d+)\)(?:\s+\[(\d+):(\d+)\])?\s*:\s+', remaining)
    if not proc_match:
        raise ValueError(f"Could not parse process info from: {line}")
    procname = proc_match.group(1)
    if procname != 'unknown':
        result['comm'] = procname
    result['pid'] = int(proc_match.group(2))
    if proc_match.group(3) is not None:
        result['uid'] = int(proc_match.group(3))
        result['gid'] = int(proc_match.group(4))
    remaining = remaining[proc_match.end():]
    types_match = re.match(r'([RCWO+D<>]+)\s+', remaining)
    if types_match:
        result['types'] = types_match.group(1)
        remaining = remaining[types_match.end():]
    device_match = re.match(r'device (\d+):(\d+) inode (\d+)', remaining)
    if device_match:
        result['device'] = {'major': int(device_match.group(1)), 'minor': int(device_match.group(2))}
        result['inode'] = int(device_match.group(3))
        return result
    parts = re.split(r'(\s+exe=|\s+,\s*parents)', remaining)
    if parts and parts[0].strip() and parts[0].strip() != '(deleted)':
        result['path'] = parts[0].strip()
    exe_match = re.search(r'\s+exe=([^\s,]+)', remaining)
    if exe_match:
        result['exe'] = exe_match.group(1)
    parents_match = re.search(r',\s*parents=(.+)$', remaining)
    if parents_match:
        parents = []
        for parent_match in re.findall(r'\(([^)]+)\)', parents_match.group(1)):
            parent = {}
            pid_match = re.search(r'pid=(\d+)', parent_match)
            if pid_match:
                parent['pid'] = int(pid_match.group(1))
            comm_match = re.search(r'comm=([^\s]+)', parent_match)
            if comm_match:
                parent['comm'] = comm_match.group(1)
            exe_match = re.search(r'exe=([^\s]+)', parent_match)
            if exe_match:
                parent['exe'] = exe_match.group(1)
            if parent:
                parents.append(parent)
        if parents:
            result['parents'] = parents
    return result

class FatraceRunner:
    """Run two fatrace in parallel, without and with --json respectively."""
    def __init__(self, *args: str):
        self.text_runner = FatraceRunnerBase([x for x in args if x!="--json"],
                                             convert_line = parse_fatrace_text_line)
        self.json_runner = FatraceRunnerJson(*args)
    def assert_log(self, condition_func: Callable[[dict], bool]) -> None:
        self.text_runner.assert_log(condition_func)
        self.json_runner.assert_log(condition_func)
    def assert_not_log(self, condition_func: Callable[[dict], bool]) -> None:
        self.text_runner.assert_not_log(condition_func)
        self.json_runner.assert_not_log(condition_func)

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

    def test_currentmount(self):
        f = FatraceRunner("--current-mount", "-s", "2", "--json")

        # Create/write/remove a file
        test_file = self.tmp_path / "test.txt"
        slow_exe(["touch", str(test_file)])
        slow_exe(["bash", "-c", f"echo hello > '{test_file}'"])
        slow_exe(["head", str(test_file)], stdout=subprocess.DEVNULL)
        slow_exe(["rm", str(test_file)])

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

        cwd = str(self.tmp_path)
        test_file_str = str(test_file)

        # file creation
        f.assert_log(lambda e: e["comm"] == "touch" and e["path"] == test_file_str and "O" in e["types"])
        f.assert_log(lambda e: e["comm"] == "touch" and e["path"] == test_file_str and "W" in e["types"])
        f.assert_log(lambda e: e["comm"] == "bash" and e["path"] == test_file_str and "W" in e["types"])

        # file reading
        f.assert_log(lambda e: e["comm"] == "head" and e["path"] == test_file_str and "R" in e["types"])

        # file deletion
        f.assert_log(lambda e: e["comm"] == "rm" and e["path"] == cwd and e["types"] == "D")

        # directory creation
        f.assert_log(lambda e: e["comm"] == "touch" and e["path"] == cwd and e["types"] == "+")
        f.assert_log(lambda e: e["comm"] == "mkdir" and e["path"] == cwd and e["types"] == "+")

        # file renaming (can be one or two events)
        f.assert_log(lambda e: e["comm"] == "mv" and e["path"] == cwd and "<" in e["types"])
        f.assert_log(lambda e: e["comm"] == "mv" and e["path"] == cwd and ">" in e["types"])

        # file moving between directories
        f.assert_log(lambda e: e["comm"] == "mv" and e["path"] == cwd and e["types"] == "<")
        f.assert_log(lambda e: e["comm"] == "mv" and e["path"] == str(dest_dir) and e["types"] == ">")

        # ELOOP symlink operations
        f.assert_log(lambda e: e["comm"] == "ln" and e["path"] == cwd and e["types"] == "+")
        f.assert_log(lambda e: e["comm"] == "rm" and e["path"] == cwd and e["types"] == "D")

    def test_command(self):
        f = FatraceRunnerText("--current-mount", "--command", "touch", "-s", "2")
        f_json = FatraceRunnerJson("--current-mount", "--command", "touch", "-s", "2", "--json")

        # Create files with different programs
        slow_exe(["touch", str(self.tmp_path / "includeme")])
        slow_exe(["dd", "if=/dev/zero", f"of={self.tmp_path}/notme", "bs=1", "count=1", "status=none"])

        # Check text log: should find touch command, but not dd nor the file it created
        f.assert_log(r"^touch.*includeme$")
        f.assert_not_log(r"notme")
        f.assert_not_log(r"^dd")

        # Check JSON log
        includeme_path = str(self.tmp_path / "includeme")
        f_json.assert_log(lambda e: e["path"] == includeme_path)
        f_json.assert_not_log(lambda e: "notme" in e["path"])
        f_json.assert_not_log(lambda e: e["comm"]=="dd")

    def test_command_long_name(self):
        # command name that exceeds TASK_COMM_LEN (16 chars)
        long_cmd = self.tmp_path / "VeryLongTouchCommand"
        exe(["cp", "/usr/bin/touch", str(long_cmd)])

        f = FatraceRunner("--current-mount", "--command", "VeryLongTouchCommand", "-s", "2", "--json")
        slow_exe([str(long_cmd), str(self.tmp_path / "hello.txt")])

        # Should find the truncated command name (first 15 chars per TASK_COMM_LEN-1)
        f.assert_log(lambda e: e["comm"]=="VeryLongTouchCo" and "W" in e["types"] and e["path"]==f"{str(self.tmp_path)}/hello.txt")

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
        slow_exe(["bash", "-c", "echo hello > world.txt"])

        f = FatraceRunner("--current-mount", "-s", "2", "--json")

        # Read existing file
        slow_exe(["head", str(mount_dir / "world.txt")], stdout=subprocess.DEVNULL)

        # Standard file operations
        test_file = mount_dir / "test.txt"
        slow_exe(["touch", str(test_file)])
        slow_exe(["bash", "-c", f"echo hello > '{test_file}'"])
        slow_exe(["rm", str(test_file)])

        # Move a file within the same directory
        slow_exe(["touch", str(test_file)])
        test_file_2 = mount_dir / "test.txt.2"
        slow_exe(["mv", str(test_file), str(test_file_2)])
        dest_dir = mount_dir / "dest"
        slow_exe(["mkdir", str(dest_dir)])
        dest_file = dest_dir / "test.txt.2"
        slow_exe(["mv", str(test_file_2), str(dest_file)])
        slow_exe(["rm", str(dest_file)])
        slow_exe(["rmdir", str(dest_dir)])

        # Create file on subvolume
        subvol_file = mount_dir / "subv1" / "sub.txt"
        slow_exe(["touch", str(subvol_file)])

        mount_str = str(mount_dir)

        # world.txt access
        f.assert_log(lambda e: "R" in e["types"] and e["path"]==str(mount_dir / 'world.txt'))

        # file operations on main filesystem
        test_file_str = str(test_file)
        f.assert_log(lambda e: e["comm"]=="touch" and "O" in e["types"] and e["path"]==test_file_str)
        f.assert_log(lambda e: e["comm"]=="touch" and "W" in e["types"] and e["path"]==test_file_str)
        f.assert_log(lambda e: e["comm"]=="bash" and "W" in e["types"] and e["path"]==test_file_str)
        f.assert_log(lambda e: e["comm"]=="rm" and e["types"] in ["", "D"] and e["path"]==mount_str)

        # directory creation
        f.assert_log(lambda e: e["comm"]=="touch" and e["types"] == "+" and e["path"]==mount_str)
        f.assert_log(lambda e: e["comm"]=="mkdir" and e["types"] == "+" and e["path"]==mount_str)

        # file renaming (can be one or two events)
        f.assert_log(lambda e: e["comm"]=="mv" and "<" in e["types"] and e["path"]==mount_str)
        f.assert_log(lambda e: e["comm"]=="mv" and ">" in e["types"] and e["path"]==mount_str)

        # file moving
        f.assert_log(lambda e: e["comm"]=="mv" and e["types"]=="<" and e["path"]==mount_str)
        f.assert_log(lambda e: e["comm"]=="mv" and e["types"]==">" and e["path"]==str(dest_dir))

        # subvolume file creation
        f.assert_log(lambda e: e["comm"]=="touch" and "O" in e["types"] and e["path"]==str(subvol_file))

    def test_exe_parents(self):
        f = FatraceRunner("--current-mount", "-s", "2", "--parents", "--exe", "--json")

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

        # Read process information
        bash_pid = int(bash_pid_file.read_text().strip())
        python_pid = int(python_pid_file.read_text().strip())
        test_pid = os.getpid()

        # Get executable paths
        touch_exe = which("touch")
        bash_exe = which("bash")
        python_exe = which("python3")
        init_comm = Path("/proc/1/comm").read_text().strip()
        init_exe = Path("/proc/1/exe").resolve()

        # Check JSON log for parent chain
        f.assert_log(lambda e: (
            e["comm"] == "touch" and
            e["path"] == str(test_file) and
            e["exe"] == str(touch_exe) and
            len(e["parents"]) >= 4 and
            e["parents"][0] == {"pid": bash_pid, "comm": "bash", "exe": str(bash_exe)} and
            e["parents"][1] == {"pid": python_pid, "comm": "python3", "exe": str(python_exe)} and
            e["parents"][2] == {"pid": test_pid, "comm": "python3", "exe": str(python_exe)} and
            e["parents"][-1] == {"pid": 1, "comm": init_comm, "exe": str(init_exe)}
        ))

    def test_user(self):
        nobody_user = pwd.getpwnam('nobody')
        nobody_uid = nobody_user.pw_uid
        nobody_gid = nobody_user.pw_gid

        test_file = self.tmp_path / "testfile.txt"
        test_file.write_text("test content")

        # Test user tracking functionality
        f = FatraceRunner("--current-mount", "--user", "-s", "4", "--json")

        def slow_exe_nobody(argv: list[str], **kwargs) -> None:
            exe(["runuser", "-u", "nobody",
                 "env", "LD_PRELOAD=" + str(TESTDIR / "slow-exit.so")] + argv,
                **kwargs)

        # read test file as root
        slow_exe(["head", str(test_file)], stdout=subprocess.DEVNULL)
        # read test file as nobody
        slow_exe_nobody(["tail", str(test_file)], stdout=subprocess.DEVNULL)

        # Create/remove a file as root
        test_file_root = self.tmp_path / "testroot.txt"
        slow_exe(["touch", str(test_file_root)])
        slow_exe(["rm", str(test_file_root)])

        # Create a world-writable directory for user operations
        user_tmp = self.tmp_path / "user_tmp"
        user_tmp.mkdir()
        user_tmp.chmod(0o1777)

        # Create/remove a file as user 'nobody'
        test_file_user = user_tmp / "testnobody.txt"
        slow_exe_nobody(["touch", str(test_file_user)])
        slow_exe_nobody(["rm", str(test_file_user)])

        test_file_str = str(test_file)
        test_file_root_str = str(test_file_root)
        test_file_user_str = str(test_file_user)

        # Reading the test file as root [0:0]
        f.assert_log(lambda e: (
            e["comm"] == "head" and
            e["uid"] == 0 and
            e["gid"] == 0 and
            "R" in e["types"] and
            e["path"] == test_file_str
        ))

        # Reading the test file as user nobody [uid:gid]
        f.assert_log(lambda e: (
            e["comm"] == "tail" and
            e["uid"] == nobody_uid and
            e["gid"] == nobody_gid and
            "R" in e["types"] and
            e["path"] == test_file_str
        ))

        # File creation as root [0:0]
        f.assert_log(lambda e: (
            e["comm"] == "touch" and
            e["uid"] == 0 and
            e["gid"] == 0 and
            "O" in e["types"] and
            e["path"] == test_file_root_str
        ))

        # File creation as user nobody [uid:gid]
        f.assert_log(lambda e: (
            e["comm"] == "touch" and
            e["uid"] == nobody_uid and
            e["gid"] == nobody_gid and
            "O" in e["types"] and
            e["path"] == test_file_user_str
        ))

    def test_json(self):
        """JSON-specific features like path_raw, UTF-8 handling, device/inode, etc."""
        f_json = FatraceRunnerJson("--current-mount", "--user", "-s", "10", "--json")

        # Test 1: Basic path tracking
        good_file = self.tmp_path / "1-good.tmp"
        slow_exe(["touch", str(good_file)])

        # Test 2: path_raw for non-UTF8 paths
        bad_file = self.tmp_path / f"2-bad-{chr(1)}.tmp"
        slow_exe(["touch", str(bad_file)])

        # Test 3: pid tracking
        pid_file = self.tmp_path / "3-pid"
        slow_exe(["bash", "-c", f"echo $$ > '{pid_file}'"])

        # Test 4: device and inode tracking
        device_file = self.tmp_path / "4-good.tmp"
        slow_exe(["touch", str(device_file)])

        # Test 5: UTF-8 test cases - keep as raw bytes for bad cases
        # (expected_result, filename_bytes, description)
        utf8_test_cases = [
            ("bad", b"\x05-tmp", "0x05"),
            ("bad", b"\x1f-tmp", "0x1f"),
            ("good", b"\x20-tmp", "0x20 space"),
            ("good", b"\x21-tmp", "0x21 !"),
            ("bad", b"\x22-tmp", "0x22 \""),
            ("good", b"\x23-tmp", "0x23 #"),
            ("good", b"\x5b-tmp", "0x5b ["),
            ("bad", b"\x5c-tmp", "0x5c \\"),
            ("good", b"\x5d-tmp", "0x5d ]"),
            ("good", b"\x7e-tmp", "0x7e ~"),
            ("bad", b"\x7f-tmp", "0x7f"),
            # 2-char UTF-8
            ("good", "\u0080-tmp".encode(), "U+0080"),
            ("good", "\u00c5-tmp".encode(), "U+00c5 Å"),
            ("bad", b"\xc3-tmp", "incomplete UTF-8"),
            ("good", "\u07ff-tmp".encode(), "U+07ff ߿"),
            # 3-char UTF-8
            ("good", "\u0800-tmp".encode(), "U+0800 ࠀ"),
            ("good", "\u0bf5-tmp".encode(), "U+0bf5 ௵"),
            ("bad", b"\xe0\xaf-tmp", "incomplete UTF-8"),
            ("good", "\ud7ff-tmp".encode(), "U+d7ff"),
            ("bad", b"\xed\xa0\x80-tmp", "surrogate U+d800"),
            ("good", "\ue000-tmp".encode(), "U+e000"),
            ("good", "\uffff-tmp".encode(), "U+ffff"),
            # 4-char UTF-8
            ("good", "\U00010000-tmp".encode(), "U+10000 𐀀"),
            ("good", "\U0001f005-tmp".encode(), "U+1f005 🀅"),
            ("bad", b"\xf0\x9f\x80-tmp", "incomplete UTF-8"),
            ("good", "\U0010ffff-tmp".encode(), "U+10ffff"),
            # continuation bytes
            ("bad", b"\x80-tmp", "0x80"),
            ("bad", b"\xbf-tmp", "0xbf"),
        ]

        created_utf8_files = []
        for expected, filename_bytes, description in utf8_test_cases:
            full_filename_bytes = b"utf8-" + expected.encode('ascii') + b"-" + filename_bytes

            # Use printf to create the exact filename with byte sequences
            printf_arg = ''.join(f'\\{b:03o}' for b in full_filename_bytes)
            slow_exe(["bash", "-c", f"touch \"$(printf '{printf_arg}')\""])

            created_utf8_files.append((expected, full_filename_bytes, description))

        # Test 1: Basic path tracking
        f_json.assert_log(lambda e: e["comm"] == "touch" and e["path"] == str(good_file))

        # Test 2: path_raw for non-UTF8 paths
        # For files with invalid UTF-8, should have path_raw instead of path
        f_json.assert_log(lambda e: e["comm"] == "touch" and
                           e["path_raw"] == list(str(bad_file).encode('utf-8')) and
                           "path" not in e)

        # Test 3: pid tracking
        recorded_pid = int(pid_file.read_text().strip())
        f_json.assert_log(lambda e: e["comm"] == "bash" and e["pid"] == recorded_pid and e["path"] == str(pid_file))

        # Test 4: device and inode tracking
        stat_result = device_file.stat()
        f_json.assert_log(lambda e: (
            e["comm"] == "touch" and
            e["path"] == str(device_file) and
            e["device"] == {"major": os.major(stat_result.st_dev), "minor": os.minor(stat_result.st_dev)} and
            e["inode"] == stat_result.st_ino
        ))

        # Test 5: UTF-8 validation - test both good and bad cases properly
        for expected, filename_bytes, description in created_utf8_files:
            # Calculate the full path bytes
            full_path_bytes = str(self.tmp_path).encode('utf-8') + b"/" + filename_bytes

            if expected == "good":
                # Good UTF-8: should be decodable and have "path" field, should NOT have "path_raw"
                file_path_str = full_path_bytes.decode('utf-8')
                f_json.assert_log(lambda e, filepath=file_path_str: (
                    e["comm"] == "touch" and
                    "comm_raw" not in e and
                    e["path"] == filepath and
                    "path_raw" not in e
                ))

            elif expected == "bad":
                # Bad UTF-8: should NOT be decodable and should have "path_raw" field as byte array
                file_bytes_list = list(full_path_bytes)
                f_json.assert_log(lambda e, filebytes=file_bytes_list: (
                    e["comm"] == "touch" and
                    "comm_raw" not in e and
                    e["path_raw"] == filebytes and
                    "path" not in e
                ))

    def test_dir(self):
        yes1 = str(self.tmp_path / "yes-1")
        yes2 = str(self.tmp_path / "yes-2")
        no1 = str(self.tmp_path / "no-1")

        exe(["mkdir", yes1])
        exe(["mkdir", yes2])
        exe(["mkdir", no1])

        fs = [
            FatraceRunner("-s", "3", "-d", yes1, f"--dir={yes2}", "--json"),
            FatraceRunner("-s", "3", "--json", "-d", yes1, "--", yes2),
            FatraceRunner("-s", "3", "--json", "--", yes1, yes2),
        ]

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

        for f in fs:
            f.assert_log    (lambda e: e["comm"] == "mkdir" and e["types"] == "+" and e["path"] == yes1)
            f.assert_not_log(lambda e: e["comm"] == "mkdir" and e["types"] == "+" and e["path"] == no1)
            f.assert_log    (lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{yes1}/yesC")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{yes1}/subA/noD")
            f.assert_log    (lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{yes2}/yesE")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{no1}/noF")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{no1}/subB/noG")
            f.assert_log    (lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{new_yes1}/yesH")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{new_yes1}/subA/noI")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{new_no1}/noJ")
            f.assert_not_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == f"{new_no1}/subB/noK")

    @unittest.skipIf("container" in os.environ, "Not supported in container environment")
    @unittest.skipIf(os.path.exists("/sysroot/ostree"), "Test does not work on OSTree")
    @unittest.skipIf(root_is_btrfs, "FANOTIFY does not work on btrfs, https://github.com/martinpitt/fatrace/issues/3")
    def test_all_mounts(self):
        f = FatraceRunner("-s", "2", "--json")

        # read a system file
        slow_exe(["head", "/etc/passwd"], stdout=subprocess.DEVNULL)

        # create file
        test_file = Path("/tmp/fatrace-test.txt")
        slow_exe(["touch", str(test_file)])
        slow_exe(["bash", "-c", f"echo hello > '{test_file}'"])

        # remove file
        slow_exe(["rm", str(test_file)])

        head_binary = which("head")

        # opening the head binary
        f.assert_log(lambda e: "R" in e["types"] and e["path"] == head_binary)
        # head accessing /etc/passwd
        f.assert_log(lambda e: "R" in e["types"] and e["path"] == "/etc/passwd")

        # create a file
        test_file_str = str(test_file)
        f.assert_log(lambda e: e["comm"] == "touch" and "O" in e["types"] and e["path"] == test_file_str)
        f.assert_log(lambda e: e["comm"] == "touch" and "W" in e["types"] and e["path"] == test_file_str)
        f.assert_log(lambda e: e["comm"] == "bash" and "W" in e["types"] and e["path"] == test_file_str)

        # remove file
        f.assert_log(lambda e: e["comm"] == "touch" and e["types"] == "+" and e["path"] == "/tmp")
        f.assert_log(lambda e: e["comm"] == "rm" and e["types"] == "D" and e["path"] == "/tmp")
