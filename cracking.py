#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict
import threading

from hashing import HashVerifier


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    tried: int


class ThreadedBruteForcer:
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

        self.verifier = verifier
        self.charset = charset

        # length <= 0 means unbounded variable-length mode
        self.length = length

        self.threads = threads
        self.chunk_size = max(1, chunk_size)
        self.base = len(charset)

        self._range_start = start_index
        self._range_end = start_index + count

        self._next_index = self._range_start
        self._index_lock = threading.Lock()

        self._internal_stop = threading.Event()
        self._external_stop = external_stop

        self._found_lock = threading.Lock()
        self._found_password: Optional[str] = None

        self._count_lock = threading.Lock()
        self._total_tested = 0

        self._threads_active = 0
        self._threads_active_lock = threading.Lock()

        self._inflight_lock = threading.Lock()
        self._inflight: Dict[int, int] = {}

    def stop(self) -> None:
        self._internal_stop.set()

    def _is_stopping(self) -> bool:
        if self._internal_stop.is_set():
            return True
        if self._external_stop is not None and self._external_stop.is_set():
            return True
        return False

    def _index_to_candidate(self, idx: int) -> str:
        if idx < 0:
            raise ValueError("idx must be >= 0")

        base = self.base

        # Unbounded variable-length mode:
        # indices cover length 1, then 2, then 3, and so on forever.
        if self.length <= 0:
            candidate_len = 1
            bucket_size = base ** candidate_len

            while idx >= bucket_size:
                idx -= bucket_size
                candidate_len += 1
                bucket_size = base ** candidate_len

            chars: List[str] = [""] * candidate_len
            for pos in range(candidate_len - 1, -1, -1):
                idx, digit = divmod(idx, base)
                chars[pos] = self.charset[digit]

            return "".join(chars)

        # Fixed-length mode
        chars: List[str] = [""] * self.length
        for pos in range(self.length - 1, -1, -1):
            idx, digit = divmod(idx, base)
            chars[pos] = self.charset[digit]
        return "".join(chars)

    def _claim_chunk(self) -> Optional[range]:
        with self._index_lock:
            if self._next_index >= self._range_end:
                return None
            start = self._next_index
            end = min(self._range_end, start + self.chunk_size)
            self._next_index = end

        with self._inflight_lock:
            self._inflight[start] = end

        return range(start, end)

    def _mark_chunk_done(self, start: int) -> None:
        with self._inflight_lock:
            self._inflight.pop(start, None)

    def _add_tested(self, n: int) -> None:
        with self._count_lock:
            self._total_tested += n

    def _set_found(self, password: str) -> None:
        with self._found_lock:
            if self._found_password is None:
                self._found_password = password
                self._internal_stop.set()

    def get_total_tested(self) -> int:
        with self._count_lock:
            return self._total_tested

    def get_threads_active(self) -> int:
        with self._threads_active_lock:
            return self._threads_active

    def get_resume_index(self) -> int:
        with self._index_lock:
            next_index = self._next_index
        with self._inflight_lock:
            if not self._inflight:
                return next_index
            lowest_inflight = min(self._inflight.keys())
        return min(next_index, lowest_inflight)

    def _worker_thread(self) -> None:
        with self._threads_active_lock:
            self._threads_active += 1

        try:
            while not self._is_stopping():
                chunk = self._claim_chunk()
                if chunk is None:
                    return

                chunk_start = chunk.start
                local_tested = 0

                try:
                    for idx in chunk:
                        if self._is_stopping():
                            break

                        candidate = self._index_to_candidate(idx)
                        local_tested += 1

                        if self.verifier.verify(candidate):
                            self._add_tested(local_tested)
                            self._set_found(candidate)
                            return

                    if local_tested:
                        self._add_tested(local_tested)
                finally:
                    self._mark_chunk_done(chunk_start)

        finally:
            with self._threads_active_lock:
                self._threads_active -= 1

    def run(self) -> CrackResult:
        threads: List[threading.Thread] = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker_thread, daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        tried = self.get_total_tested()
        with self._found_lock:
            pw = self._found_password

        return CrackResult(found=(pw is not None), password=pw, tried=tried)