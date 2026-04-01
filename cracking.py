#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List
import multiprocessing as mp
import threading
import time
import queue

from hashing import build_verifier, HashVerifier


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    tried: int


def _index_to_candidate_fixed(charset: str, length: int, idx: int) -> str:
    base = len(charset)
    chars: List[str] = [""] * length
    for pos in range(length - 1, -1, -1):
        idx, digit = divmod(idx, base)
        chars[pos] = charset[digit]
    return "".join(chars)


def _index_to_candidate_unbounded(charset: str, idx: int) -> str:
    if idx < 0:
        raise ValueError("idx must be >= 0")

    base = len(charset)
    candidate_len = 1
    bucket_size = base ** candidate_len

    while idx >= bucket_size:
        idx -= bucket_size
        candidate_len += 1
        bucket_size = base ** candidate_len

    chars: List[str] = [""] * candidate_len
    for pos in range(candidate_len - 1, -1, -1):
        idx, digit = divmod(idx, base)
        chars[pos] = charset[digit]

    return "".join(chars)


def _index_to_candidate(charset: str, length: int, idx: int) -> str:
    if length <= 0:
        return _index_to_candidate_unbounded(charset, idx)
    return _index_to_candidate_fixed(charset, length, idx)


def _worker_process(
    full_hash: str,
    charset: str,
    length: int,
    start_index: int,
    end_index: int,
    stop_event,
    result_queue,
    progress_queue,
    report_every: int = 500,
) -> None:
    verifier = build_verifier(full_hash)
    local_tested = 0
    last_report_index = start_index

    try:
        for idx in range(start_index, end_index):
            if stop_event.is_set():
                break

            candidate = _index_to_candidate(charset, length, idx)
            local_tested += 1

            if verifier.verify(candidate):
                if local_tested > 0:
                    progress_queue.put(("progress", local_tested, idx + 1))
                result_queue.put(("found", candidate))
                stop_event.set()
                return

            if local_tested % report_every == 0:
                progress_queue.put(("progress", report_every, idx + 1))
                last_report_index = idx + 1

        remaining = local_tested % report_every
        if remaining:
            progress_queue.put(("progress", remaining, end_index))

        progress_queue.put(("done", 0, end_index))

    except Exception as e:
        progress_queue.put(("error", 0, f"{type(e).__name__}: {e}"))


class ThreadedBruteForcer:
    """
    Same external API as before, but uses multiprocessing internally.
    """

    def __init__(
        self,
        verifier: HashVerifier,
        charset: str,
        length: int,
        threads: int,
        start_index: int,
        count: int,
        *,
        chunk_size: int = 2000,
        external_stop: Optional[threading.Event] = None,
    ) -> None:
        if threads <= 0:
            raise ValueError("threads must be > 0")
        if not charset:
            raise ValueError("charset must be non-empty")
        if start_index < 0:
            raise ValueError("start_index must be >= 0")
        if count < 0:
            raise ValueError("count must be >= 0")

        full_hash = getattr(verifier, "full_hash", None)
        if not isinstance(full_hash, str) or not full_hash:
            raise ValueError("verifier must expose a non-empty full_hash string")

        self.full_hash = full_hash
        self.charset = charset
        self.length = length
        self.threads = threads
        self.chunk_size = max(1, chunk_size)

        self._range_start = start_index
        self._range_end = start_index + count
        self._external_stop = external_stop

        self._ctx = mp.get_context("spawn")
        self._stop_event = self._ctx.Event()
        self._result_queue = self._ctx.Queue()
        self._progress_queue = self._ctx.Queue()

        self._processes: List[mp.Process] = []

        self._total_tested = 0
        self._threads_active = 0
        self._found_password: Optional[str] = None

        self._subranges: List[tuple[int, int]] = []
        self._resume_positions: List[int] = []

    def stop(self) -> None:
        self._stop_event.set()

    def _split_ranges(self) -> List[tuple[int, int]]:
        total = self._range_end - self._range_start
        if total <= 0:
            return []

        workers = min(self.threads, total)
        base = total // workers
        rem = total % workers

        ranges: List[tuple[int, int]] = []
        cursor = self._range_start

        for i in range(workers):
            size = base + (1 if i < rem else 0)
            sub_start = cursor
            sub_end = cursor + size
            ranges.append((sub_start, sub_end))
            cursor = sub_end

        return ranges

    def _start_processes(self) -> None:
        self._subranges = self._split_ranges()
        self._resume_positions = [start for start, _ in self._subranges]

        for sub_start, sub_end in self._subranges:
            p = self._ctx.Process(
                target=_worker_process,
                args=(
                    self.full_hash,
                    self.charset,
                    self.length,
                    sub_start,
                    sub_end,
                    self._stop_event,
                    self._result_queue,
                    self._progress_queue,
                ),
            )
            p.start()
            self._processes.append(p)

        self._threads_active = len(self._processes)

    def get_total_tested(self) -> int:
        return self._total_tested

    def get_threads_active(self) -> int:
        return self._threads_active

    def get_resume_index(self) -> int:
        if not self._resume_positions:
            return self._range_end
        return min(self._resume_positions)

    def _drain_progress(self) -> None:
        while True:
            try:
                kind, amount, extra = self._progress_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "progress":
                self._total_tested += int(amount)

                resume_index = int(extra)
                for i, (_start, end) in enumerate(self._subranges):
                    if self._resume_positions[i] < end:
                        self._resume_positions[i] = max(self._resume_positions[i], resume_index)
                        break

            elif kind == "done":
                self._threads_active = max(0, self._threads_active - 1)

            elif kind == "error":
                self._threads_active = max(0, self._threads_active - 1)
                print(f"[cracking.py child error] {extra}")

    def run(self) -> CrackResult:
        self._start_processes()

        try:
            while True:
                if self._external_stop is not None and self._external_stop.is_set():
                    self._stop_event.set()

                self._drain_progress()

                try:
                    kind, payload = self._result_queue.get(timeout=0.1)
                    if kind == "found":
                        self._found_password = payload
                        self._stop_event.set()
                except queue.Empty:
                    pass

                if all(not p.is_alive() for p in self._processes):
                    self._drain_progress()
                    break

                if self._stop_event.is_set():
                    time.sleep(0.05)

            for p in self._processes:
                p.join(timeout=1.0)

            for p in self._processes:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.5)

            return CrackResult(
                found=(self._found_password is not None),
                password=self._found_password,
                tried=self._total_tested,
            )

        finally:
            self._stop_event.set()
            for p in self._processes:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.5)