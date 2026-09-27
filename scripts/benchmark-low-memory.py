"""Run an existing Rust benchmark inside a Windows process-memory Job limit.

No dependencies. The child is assigned while suspended, before any test code runs.
Usage: python scripts/benchmark-low-memory.py TEST_EXE REPORT OUTPUT_DIR [MIB]
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if os.name != "nt":
    raise SystemExit("This harness requires Windows Job Objects")
k = c.WinDLL("kernel32", use_last_error=True)
psapi = c.WinDLL("psapi", use_last_error=True)
SIZE = c.c_size_t


class Basic(c.Structure):
    _fields_ = [("per_process", c.c_int64), ("per_job", c.c_int64),
                ("flags", w.DWORD), ("min_ws", SIZE), ("max_ws", SIZE),
                ("active", w.DWORD), ("affinity", SIZE),
                ("priority", w.DWORD), ("scheduling", w.DWORD)]


class IO(c.Structure):
    _fields_ = [(x, c.c_uint64) for x in ("read_ops", "write_ops", "other_ops",
                                        "read_bytes", "write_bytes", "other_bytes")]


class Extended(c.Structure):
    _fields_ = [("basic", Basic), ("io", IO), ("process_memory", SIZE),
                ("job_memory", SIZE), ("peak_process", SIZE), ("peak_job", SIZE)]


class Startup(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                ("title", w.LPWSTR), *[(x, w.DWORD) for x in
                ("x", "y", "width", "height", "xchars", "ychars", "fill", "flags")],
                ("show", w.WORD), ("reserved2_size", w.WORD),
                ("reserved2", c.c_void_p), ("stdin", w.HANDLE),
                ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class Process(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE),
                ("pid", w.DWORD), ("tid", w.DWORD)]


class Counters(c.Structure):
    _fields_ = [("cb", w.DWORD), ("faults", w.DWORD), *[(x, SIZE) for x in
                ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged",
                 "nonpaged", "commit", "peak_commit", "private")]]


def bind(lib, name, args, result):
    f = getattr(lib, name)
    f.argtypes, f.restype = args, result
    return f


create_job = bind(k, "CreateJobObjectW", [c.c_void_p, w.LPCWSTR], w.HANDLE)
set_job = bind(k, "SetInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL)
query_job = bind(k, "QueryInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL)
create = bind(k, "CreateProcessW", [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p,
              w.BOOL, w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(Process)], w.BOOL)
assign = bind(k, "AssignProcessToJobObject", [w.HANDLE, w.HANDLE], w.BOOL)
resume = bind(k, "ResumeThread", [w.HANDLE], w.DWORD)
wait = bind(k, "WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD)
exit_code = bind(k, "GetExitCodeProcess", [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL)
memory = bind(psapi, "GetProcessMemoryInfo", [w.HANDLE, c.POINTER(Counters), w.DWORD], w.BOOL)
close = bind(k, "CloseHandle", [w.HANDLE], w.BOOL)
terminate = bind(k, "TerminateProcess", [w.HANDLE, w.UINT], w.BOOL)


def checked(value):
    if not value:
        raise c.WinError(c.get_last_error())
    return value


exe, report, output = (Path(x).resolve() for x in sys.argv[1:4])
limit = int(sys.argv[4]) if len(sys.argv) > 4 else 512
output.mkdir(parents=True, exist_ok=True)
os.environ["DSW_BENCH_SARIF"] = str(report)
job = checked(create_job(None, None))
info = Extended()
info.basic.flags = 0x100 | 0x2000  # PROCESS_MEMORY | KILL_ON_JOB_CLOSE
info.process_memory = limit * 1024 * 1024
checked(set_job(job, 9, c.byref(info), c.sizeof(info)))
pi = Process()
started = time.monotonic()
try:
    import msvcrt
    with (output / "benchmark.log").open("wb") as log, open(os.devnull, "rb") as null:
        out_handle = msvcrt.get_osfhandle(log.fileno())
        in_handle = msvcrt.get_osfhandle(null.fileno())
        os.set_handle_inheritable(out_handle, True)
        os.set_handle_inheritable(in_handle, True)
        si = Startup()
        si.cb, si.flags = c.sizeof(si), 0x100
        si.stdout = si.stderr = out_handle
        si.stdin = in_handle
        cmd = c.create_unicode_buffer(subprocess.list2cmdline([
            str(exe), "--ignored", "streaming_large_benchmark", "--nocapture"]))
        checked(create(str(exe), cmd, None, None, True, 0x4 | 0x08000000,
                       None, str(exe.parent), c.byref(si), c.byref(pi)))
        checked(assign(job, pi.process))
        if resume(pi.thread) == 0xFFFFFFFF:
            raise c.WinError(c.get_last_error())
        peak_ws = peak_commit = 0
        while True:
            counters = Counters()
            counters.cb = c.sizeof(counters)
            if memory(pi.process, c.byref(counters), c.sizeof(counters)):
                peak_ws = max(peak_ws, counters.peak_ws)
                peak_commit = max(peak_commit, counters.peak_commit)
            status = wait(pi.process, 100)
            if status == 0:
                break
            if status != 258:
                raise c.WinError(c.get_last_error())
        code = w.DWORD()
        checked(exit_code(pi.process, c.byref(code)))
        checked(query_job(job, 9, c.byref(info), c.sizeof(info), None))
        result = dict(limit_bytes=info.process_memory, limit_enforced_before_start=True,
                      peak_working_set_bytes=peak_ws, peak_commit_bytes=peak_commit,
                      job_peak_process_bytes=info.peak_process, exit_code=code.value,
                      elapsed_seconds=round(time.monotonic() - started, 3),
                      executable=str(exe), report=str(report))
        (output / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        sys.exit(code.value)
finally:
    if pi.process:
        # Also cleans up a suspended child if assignment/resume fails.
        terminate(pi.process, 1)
        close(pi.process)
    if pi.thread:
        close(pi.thread)
    close(job)
