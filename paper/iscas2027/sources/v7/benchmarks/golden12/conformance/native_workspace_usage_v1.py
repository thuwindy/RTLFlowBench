"""Read-only, no-follow workspace byte sampling; no file contents or names output.

Run under the owning rootless user namespace for subordinate-UID workspaces.
This samples regular-file logical bytes, not disk blocks or unsampled peaks.
"""

import json
import os
from pathlib import Path
import stat
import sys


SCHEMA = "chipflow.native_workspace_usage.v1"


def scan(root, *, maximum_entries=100000, maximum_depth=64):
    if type(maximum_entries) is not int or maximum_entries < 1:
        raise ValueError("invalid_entry_limit")
    if type(maximum_depth) is not int or not 1 <= maximum_depth <= 128:
        raise ValueError("invalid_depth_limit")
    root = Path(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    result = {
        "schema_version": SCHEMA,
        "observed_regular_file_bytes": 0,
        "regular_file_count": 0,
        "visited_entry_count": 0,
        "error_count": 0,
        "unsafe_entry_count": 0,
        "limit_reached": False,
        "complete": False,
    }

    def walk(fd, depth, device):
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    if result["visited_entry_count"] >= maximum_entries:
                        result["limit_reached"] = True
                        return
                    result["visited_entry_count"] += 1
                    try:
                        info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                        if info.st_dev != device:
                            result["unsafe_entry_count"] += 1
                        elif stat.S_ISDIR(info.st_mode):
                            if depth >= maximum_depth:
                                result["limit_reached"] = True
                                continue
                            child = os.open(entry.name, flags, dir_fd=fd)
                            try:
                                opened = os.fstat(child)
                                if (opened.st_dev, opened.st_ino) != (
                                    info.st_dev,
                                    info.st_ino,
                                ):
                                    result["error_count"] += 1
                                else:
                                    walk(child, depth + 1, device)
                            finally:
                                os.close(child)
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            result["observed_regular_file_bytes"] += info.st_size
                            result["regular_file_count"] += 1
                        else:
                            # No symlink, FIFO, socket, device or hard-link traversal.
                            result["unsafe_entry_count"] += 1
                    except OSError:
                        result["error_count"] += 1
        except OSError:
            result["error_count"] += 1

    try:
        fd = os.open(root, flags)
    except OSError:
        result["error_count"] += 1
    else:
        try:
            walk(fd, 0, os.fstat(fd).st_dev)
        finally:
            os.close(fd)
    result["complete"] = not (
        result["error_count"] or result["unsafe_entry_count"] or result["limit_reached"]
    )
    return result


class Accumulator:
    """Incomplete sampling preserves partial observations, not fictional zero."""

    def __init__(self):
        self.sample_count = 0
        self.failed_probe_count = 0
        self.incomplete_sample_count = 0
        self.observed_peak_bytes = None
        self.rows = []

    def observe(self, sample, *, started_ns, completed_ns):
        keys = {
            "schema_version",
            "observed_regular_file_bytes",
            "regular_file_count",
            "visited_entry_count",
            "error_count",
            "unsafe_entry_count",
            "limit_reached",
            "complete",
        }
        if (
            not isinstance(sample, dict)
            or set(sample) != keys
            or sample["schema_version"] != SCHEMA
        ):
            raise ValueError("invalid_workspace_sample")
        for key in [
            "observed_regular_file_bytes",
            "regular_file_count",
            "visited_entry_count",
            "error_count",
            "unsafe_entry_count",
        ]:
            if type(sample[key]) is not int or sample[key] < 0:
                raise ValueError("invalid_workspace_counter")
        if (
            type(sample["complete"]) is not bool
            or type(sample["limit_reached"]) is not bool
        ):
            raise ValueError("invalid_workspace_completeness")
        expected = not (
            sample["error_count"]
            or sample["unsafe_entry_count"]
            or sample["limit_reached"]
        )
        if (
            sample["complete"] != expected
            or sample["regular_file_count"] > sample["visited_entry_count"]
        ):
            raise ValueError("inconsistent_workspace_sample")
        if (
            type(started_ns) is not int
            or type(completed_ns) is not int
            or not 0 <= started_ns <= completed_ns
        ):
            raise ValueError("invalid_workspace_sample_interval")
        if self.rows and started_ns < self.rows[-1]["completed_monotonic_ns"]:
            raise ValueError("workspace_sample_clock_reversed")
        self.sample_count += 1
        self.incomplete_sample_count += int(not sample["complete"])
        self.observed_peak_bytes = max(
            self.observed_peak_bytes or 0, sample["observed_regular_file_bytes"]
        )
        self.rows.append(
            {
                "started_monotonic_ns": started_ns,
                "completed_monotonic_ns": completed_ns,
                **sample,
            }
        )

    def failed_probe(self):
        self.failed_probe_count += 1

    def summary(self):
        complete = (
            self.sample_count > 0
            and self.failed_probe_count == 0
            and self.incomplete_sample_count == 0
        )
        return {
            "schema_version": "chipflow.native_workspace_sampling.v1",
            "sample_count": self.sample_count,
            "failed_probe_count": self.failed_probe_count,
            "incomplete_sample_count": self.incomplete_sample_count,
            "observed_peak_regular_file_bytes": self.observed_peak_bytes,
            "sampled_peak_scratch_bytes": self.observed_peak_bytes
            if complete
            else None,
            "sampling_complete": complete,
            "exact_peak_proven": False,
            "scope": "sampled logical regular-file bytes beneath actual workflow workspace; excludes collector and read-only inputs",
        }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("one_workspace_root_required")
    print(json.dumps(scan(sys.argv[1]), sort_keys=True, allow_nan=False))
