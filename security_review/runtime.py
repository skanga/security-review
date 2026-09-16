"""Cooperative run context and bounded supervision of owned subprocesses."""
from contextvars import ContextVar
from dataclasses import dataclass
import os
import signal
import subprocess
import threading
import time


class Cancelled(Exception):
    pass


class CancellationToken:
    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    def check(self):
        if self._event.is_set():
            raise Cancelled("Review cancelled")


@dataclass
class Execution:
    deadline: float
    cancellation: CancellationToken
    clock: object = time.monotonic

    def check(self):
        self.cancellation.check()
        if self.clock() >= self.deadline:
            raise TimeoutError("Review deadline exhausted")


execution = ContextVar("security_review_execution", default=None)


def checkpoint():
    context = execution.get()
    if context:
        context.check()


def run_process(command, *, cwd=None, env=None, input=None, timeout=30, limit=8 * 1024 * 1024):
    """No shell. Output is bounded while streaming; only this process tree is stopped."""
    checkpoint()
    deadline = time.monotonic() + timeout
    job = None
    if os.name == "nt":
        from .windows_job import WindowsJob
        job = WindowsJob()
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004} if job else {"start_new_session": True}
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
        if job:
            try:
                job.assign_and_resume(process)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
    except BaseException:
        if job:
            job.close()
        raise
    chunks = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(stream, index):
        try:
            while data := stream.read(8192):
                if len(chunks[index]) + len(data) > limit:
                    overflow.set()
                    break
                chunks[index].extend(data)
        finally:
            stream.close()

    def feed():
        try:
            if input is not None:
                process.stdin.write(input.encode("utf-8") if isinstance(input, str) else input)
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    threads = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for thread in threads:
        thread.start()
    try:
        while process.poll() is None:
            checkpoint()
            if time.monotonic() >= deadline:
                raise TimeoutError("Subprocess deadline exhausted")
            if overflow.is_set():
                raise ValueError("Subprocess output limit exceeded")
            time.sleep(0.02)
        if job:
            job.close()  # Also closes descendant-held pipes after parent completion.
        for thread in threads:
            thread.join(timeout=1)
        checkpoint()
        if overflow.is_set():
            raise ValueError("Subprocess output limit exceeded")
        if any(thread.is_alive() for thread in threads):
            raise ValueError("Subprocess pipes remained open")
        return subprocess.CompletedProcess(command, process.returncode, bytes(chunks[0]), bytes(chunks[1]))
    finally:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif job:
            job.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=1)
