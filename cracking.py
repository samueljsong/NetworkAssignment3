#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List
import multiprocessing as mp
import threading
import time
import queue

from hashing import HashVerifier, build_verifier


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


def _crack_subrange(
    full_hash: str,
    charset: str,
    length: int,
    sub_start: int,
    sub_end: int,
    stop_event: mp.synchronize.Event,
    found_queue: mp.Queue,
    total_tested,
    current_index,
    active_flag,
    done_flag,
    report_every: int = 250,
) -> None:
    verifier = build_verifier(full_hash)

    with active_flag.get_lock():
        active_flag.value = 1

    local_tested = 0
    last_report_index = sub_start

    try:
        for idx in range(sub_start, sub_end):
            if stop_event.is_set():
                break

            candidate = _index_to_candidate(charset, length, idx)
            local_tested += 1

            if verifier.verify(candidate):
                with total_tested.get_lock():
                    total_tested.value += local_tested
                with current_index.get_lock():
                    current_index.value = idx + 1

                found_queue.put(candidate)
                stop_event.set()
                return

            if local_tested % report_every == 0:
                with total_tested.get_lock():
                    total_tested.value += report_every
                with current_index.get_lock():
                    current_index.value = idx + 1
                last_report_index = idx + 1

        remaining = local_tested % report_every
        if remaining:
            with total_tested.get_lock():
                total_tested.value += remaining

        with current_index.get_lock():
            if stop_event.is_set():
                # conservative resume point
                current_index.value = max(current_index.value, last_report_index)
            else:
                current_index.value = sub_end

    finally:
        with done_flag.get_lock():
            done_flag.value = 1
        with active_flag.get_lock():
            active_flag.value = 0


class ThreadedBruteForcer:
    """
    Keeps the same external interface so worker.py does not need major changes,
    but internally uses multiprocessing instead of threading for the actual cracking.
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
        self._found_queue: mp.Queue = self._ctx.Queue()

        self._total_tested = self._ctx.Value("Q", 0)
        self._processes: List[mp.Process] = []

        self._current_indices = []
        self._active_flags = []
        self._done_flags = []

        self._found_password: Optional[str] = None

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

    def get_total_tested(self) -> int:
        with self._total_tested.get_lock():
            return int(self._total_tested.value)

    def get_threads_active(self) -> int:
        active = 0
        for flag in self._active_flags:
            with flag.get_lock():
                active += int(flag.value)
        return active

    def get_resume_index(self) -> int:
        if not self._current_indices:
            return self._range_end

        unfinished_positions: List[int] = []

        for idx_value, done_flag in zip(self._current_indices, self._done_flags):
            with done_flag.get_lock():
                done = bool(done_flag.value)
            if not done:
                with idx_value.get_lock():
                    unfinished_positions.append(int(idx_value.value))

        if unfinished_positions:
            return min(unfinished_positions)

        return self._range_end

    def _start_processes(self) -> None:
        for sub_start, sub_end in self._split_ranges():
            current_index = self._ctx.Value("Q", sub_start)
            active_flag = self._ctx.Value("b", 0)
            done_flag = self._ctx.Value("b", 0)

            proc = self._ctx.Process(
                target=_crack_subrange,
                args=(
                    self.full_hash,
                    self.charset,
                    self.length,
                    sub_start,
                    sub_end,
                    self._stop_event,
                    self._found_queue,
                    self._total_tested,
                    current_index,
                    active_flag,
                    done_flag,
                ),
                daemon=True,
            )

            self._current_indices.append(current_index)
            self._active_flags.append(active_flag)
            self._done_flags.append(done_flag)
            self._processes.append(proc)
            proc.start()

    def run(self) -> CrackResult:
        self._start_processes()

        try:
            while True:
                if self._external_stop is not None and self._external_stop.is_set():
                    self._stop_event.set()

                try:
                    pw = self._found_queue.get(timeout=0.1)
                    self._found_password = pw
                    self._stop_event.set()
                except queue.Empty:
                    pass

                if all(not p.is_alive() for p in self._processes):
                    break

                if self._stop_event.is_set():
                    # give children a moment to exit cleanly
                    time.sleep(0.05)

            for p in self._processes:
                p.join(timeout=1.0)

            for p in self._processes:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.5)

            tried = self.get_total_tested()
            return CrackResult(
                found=(self._found_password is not None),
                password=self._found_password,
                tried=tried,
            )

        finally:
            self._stop_event.set()
            for p in self._processes:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.5)