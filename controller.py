#!/usr/bin/env python3
from __future__ import annotations

import argparse
import selectors
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Deque

from common import (
    MessageIO,
    supported_charset_79,
    PROTOCOL_VERSION,
    heartbeat_req_dict,
    no_more_work_dict,
    stop_dict,
)
from hashing import detect_algorithm_name
from messages import (
    RegisterMessage,
    JobMessage,
    ChunkAssignMessage,
    ChunkDoneMessage,
    WorkerDoneMessage,
    ResultMessage,
)


class ShadowParseError(Exception):
    pass


@dataclass(frozen=True)
class ShadowEntry:
    username: str
    full_hash: str
    algo_name: str


class ShadowParser:
    @staticmethod
    def parse_shadow_file(shadow_file: str, username: str) -> ShadowEntry:
        with open(shadow_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line or ":" not in line:
                    continue
                if not line.startswith(username + ":"):
                    continue
                parts = line.strip().split(":")
                if len(parts) < 2:
                    raise ShadowParseError("Malformed shadow line.")
                full_hash = parts[1]
                if not full_hash or full_hash in ("*", "!", "!!"):
                    raise ShadowParseError("User has no usable password hash in the shadow file.")
                algo = detect_algorithm_name(full_hash)
                return ShadowEntry(username=username, full_hash=full_hash, algo_name=algo)
        raise ShadowParseError("User not found in shadow file.")


@dataclass
class Timings:
    parse_time: float = 0.0
    total_runtime: float = 0.0
    dispatch_overhead: float = 0.0
    assignments_issued: int = 0
    checkpoints_received: int = 0
    worker_runtimes: Dict[str, float] = field(default_factory=dict)


@dataclass
class InFlightChunk:
    chunk_id: int
    start: int
    count: int
    resume_index: int
    assigned_at: float
    last_checkpoint_at: float


@dataclass
class WorkerState:
    sock: socket.socket
    addr: Tuple[str, int]
    worker_id: str
    threads: int
    connected_at: float
    registered: bool = False
    total_tested: int = 0
    last_seen: float = 0.0
    current_chunk: Optional[InFlightChunk] = None
    chunks_completed: int = 0


class ChunkAllocator:
    def __init__(self, total_space: int, chunk_size: int) -> None:
        self.total_space = int(total_space)
        self.chunk_size = int(chunk_size)
        self.next_index = 0
        self.next_chunk_id = 1
        self.pending: Deque[Tuple[int, int]] = deque()

    def requeue(self, start: int, count: int) -> None:
        if count <= 0:
            return
        self.pending.appendleft((int(start), int(count)))

    def claim(self) -> Optional[ChunkAssignMessage]:
        if self.pending:
            start, count = self.pending.popleft()
            cid = self.next_chunk_id
            self.next_chunk_id += 1
            return ChunkAssignMessage(chunk_id=cid, start=start, count=count)

        if self.next_index >= self.total_space:
            return None

        start = self.next_index
        count = min(self.chunk_size, self.total_space - start)
        cid = self.next_chunk_id
        self.next_chunk_id += 1
        self.next_index += count
        return ChunkAssignMessage(chunk_id=cid, start=start, count=count)

    def exhausted(self) -> bool:
        return self.next_index >= self.total_space and not self.pending


class ControllerApp:
    def __init__(
        self,
        shadow_file: str,
        username: str,
        port: int,
        heartbeat_seconds: float,
        chunk_size: int,
        checkpoint_interval: int,
        length: int,
        min_workers: int,
    ) -> None:
        self.shadow_file = shadow_file
        self.username = username
        self.port = port
        self.heartbeat_seconds = heartbeat_seconds
        self.chunk_size = chunk_size
        self.checkpoint_interval = checkpoint_interval
        self.length = length
        self.min_workers = min_workers

        self._workers: Dict[socket.socket, WorkerState] = {}
        self._sel = selectors.DefaultSelector()

        self._found_password: Optional[str] = None
        self._found_by: Optional[str] = None
        self._job_done = False

    def _safe_send(self, sock: socket.socket, obj: dict) -> bool:
        try:
            MessageIO.send_msg(sock, obj)
            return True
        except Exception:
            return False

    def _broadcast(self, obj: dict) -> None:
        for ws in list(self._workers.values()):
            self._safe_send(ws.sock, obj)

    def _registered_workers(self) -> int:
        return sum(1 for w in self._workers.values() if w.registered)

    def _requeue_if_needed(self, ws: WorkerState, allocator: ChunkAllocator) -> None:
        if ws.current_chunk is None:
            return

        chunk = ws.current_chunk
        end = chunk.start + chunk.count
        resume = max(chunk.start, min(chunk.resume_index, end))

        if resume < end:
            remaining = end - resume
            allocator.requeue(resume, remaining)
            print(
                f"[RECOVER] requeued unfinished work from worker={ws.worker_id} "
                f"start={resume} count={remaining}"
            )

        ws.current_chunk = None

    def _close_worker(self, sock: socket.socket, allocator: ChunkAllocator) -> None:
        ws = self._workers.get(sock)
        if ws is not None:
            self._requeue_if_needed(ws, allocator)

        try:
            self._sel.unregister(sock)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        self._workers.pop(sock, None)

    def _check_timeouts(self, allocator: ChunkAllocator) -> None:
        now = time.perf_counter()
        timeout = max(2.0, self.heartbeat_seconds * 2.5)

        for sock, ws in list(self._workers.items()):
            if not ws.registered:
                continue
            if now - ws.last_seen > timeout:
                print(f"[TIMEOUT] worker {ws.worker_id} lost liveness")
                self._close_worker(sock, allocator)

    def run(self) -> int:
        t0 = time.perf_counter()
        timings = Timings()

        t_parse0 = time.perf_counter()
        entry = ShadowParser.parse_shadow_file(self.shadow_file, self.username)
        timings.parse_time = time.perf_counter() - t_parse0

        charset = supported_charset_79()
        total_space = len(charset) ** self.length
        allocator = ChunkAllocator(total_space=total_space, chunk_size=self.chunk_size)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", self.port))
        server.listen()
        server.setblocking(False)
        self._sel.register(server, selectors.EVENT_READ, data="ACCEPT")

        print(f"Controller listening on port {self.port} (protocol v{PROTOCOL_VERSION})")
        print(f"Target user: {entry.username}  Algo: {entry.algo_name}")
        print(f"Search space: |charset|={len(charset)} length={self.length} => total={total_space}")
        print(f"chunk_size={self.chunk_size} heartbeat={self.heartbeat_seconds}s checkpoint={self.checkpoint_interval}")

        next_hb = time.perf_counter() + self.heartbeat_seconds

        try:
            while True:
                now = time.perf_counter()

                if now >= next_hb:
                    for ws in list(self._workers.values()):
                        if ws.registered:
                            if not self._safe_send(ws.sock, heartbeat_req_dict()):
                                self._close_worker(ws.sock, allocator)
                    next_hb = now + self.heartbeat_seconds

                self._check_timeouts(allocator)

                events = self._sel.select(timeout=0.25)

                for key, _mask in events:
                    if key.data == "ACCEPT":
                        conn, addr = server.accept()
                        conn.setblocking(False)
                        self._sel.register(conn, selectors.EVENT_READ, data="WORKER")
                        self._workers[conn] = WorkerState(
                            sock=conn,
                            addr=addr,
                            worker_id="(unregistered)",
                            threads=0,
                            connected_at=time.perf_counter(),
                            last_seen=time.perf_counter(),
                        )
                        print(f"Worker connected from {addr}")
                        continue

                    sock = key.fileobj
                    if sock not in self._workers:
                        continue
                    ws = self._workers[sock]

                    try:
                        msg = MessageIO.recv_msg(sock)
                    except Exception:
                        self._close_worker(sock, allocator)
                        continue

                    ws.last_seen = time.perf_counter()
                    mtype = msg.get("type")

                    if mtype == "REGISTER":
                        reg = RegisterMessage.from_dict(msg)
                        ws.worker_id = reg.worker_id
                        ws.threads = reg.threads
                        ws.registered = True

                        job = JobMessage(
                            full_hash=entry.full_hash,
                            length=self.length,
                            charset=charset,
                            chunk_size=self.chunk_size,
                            heartbeat_seconds=self.heartbeat_seconds,
                            checkpoint_interval=self.checkpoint_interval,
                        )
                        t_dispatch0 = time.perf_counter()
                        ok = self._safe_send(sock, job.to_dict())
                        timings.dispatch_overhead += (time.perf_counter() - t_dispatch0)
                        if not ok:
                            self._close_worker(sock, allocator)
                            continue

                        print(f"Registered worker_id={ws.worker_id} threads={ws.threads} from {ws.addr}")
                        continue

                    if mtype == "HEARTBEAT_RESP":
                        worker_id = str(msg.get("worker_id", ws.worker_id))
                        delta = int(msg.get("delta_tested", 0))
                        total = int(msg.get("total_tested", ws.total_tested + delta))
                        ws.total_tested = total

                        chunk_id = msg.get("current_chunk_id", None)
                        print(
                            f"[HB] {worker_id} delta={delta} total={total} "
                            f"active={int(msg.get('threads_active', 0))} chunk={chunk_id}"
                        )
                        continue

                    if mtype == "CHECKPOINT":
                        timings.checkpoints_received += 1
                        if ws.current_chunk is not None:
                            resume_index = int(msg.get("resume_index", ws.current_chunk.resume_index))
                            chunk_start = ws.current_chunk.start
                            chunk_end = chunk_start + ws.current_chunk.count
                            ws.current_chunk.resume_index = max(chunk_start, min(resume_index, chunk_end))
                            ws.current_chunk.last_checkpoint_at = time.perf_counter()

                        print(
                            f"[CKPT] worker={ws.worker_id} "
                            f"chunk={msg.get('chunk_id')} resume_index={msg.get('resume_index')}"
                        )
                        continue

                    if mtype == "WORK_REQUEST":
                        if self._found_password is not None:
                            self._safe_send(sock, stop_dict("FOUND_ELSEWHERE"))
                            continue

                        if self._registered_workers() < self.min_workers:
                            self._safe_send(sock, {"type": "RETRY_LATER", "v": PROTOCOL_VERSION})
                            continue

                        assign = allocator.claim()
                        if assign is None:
                            self._safe_send(sock, no_more_work_dict())
                        else:
                            ws.current_chunk = InFlightChunk(
                                chunk_id=assign.chunk_id,
                                start=assign.start,
                                count=assign.count,
                                resume_index=assign.start,
                                assigned_at=time.perf_counter(),
                                last_checkpoint_at=time.perf_counter(),
                            )
                            timings.assignments_issued += 1
                            self._safe_send(sock, assign.to_dict())
                        continue

                    if mtype == "CHUNK_DONE":
                        done = ChunkDoneMessage.from_dict(msg)
                        if ws.current_chunk is not None and ws.current_chunk.chunk_id == done.chunk_id:
                            ws.current_chunk = None
                        ws.chunks_completed += 1

                        if done.found and done.password:
                            self._found_password = done.password
                            self._found_by = ws.worker_id
                            self._job_done = True
                            print(f"FOUND by worker {ws.worker_id}: password='{done.password}' (chunk_id={done.chunk_id})")
                            self._broadcast(stop_dict("PASSWORD_FOUND"))
                            timings.total_runtime = time.perf_counter() - t0
                            self._report(entry, timings, found=True, password=done.password, found_by=ws.worker_id)
                            return 0

                        continue

                    if mtype == "WORKER_DONE":
                        worker_done = WorkerDoneMessage.from_dict(msg)
                        timings.worker_runtimes[worker_done.worker_id] = worker_done.runtime_sec
                        print(
                            f"[WORKER_DONE] worker={worker_done.worker_id} "
                            f"runtime={worker_done.runtime_sec:.4f}s "
                            f"chunks={worker_done.chunks_completed} "
                            f"tested={worker_done.total_tested}"
                        )
                        continue

                    if mtype == "RESULT":
                        res = ResultMessage.from_dict(msg)
                        if res.found and res.password:
                            self._found_password = res.password
                            self._found_by = ws.worker_id
                            self._job_done = True
                            print(f"FOUND (RESULT) by worker {ws.worker_id}: password='{res.password}'")
                            self._broadcast(stop_dict("PASSWORD_FOUND"))
                            timings.total_runtime = time.perf_counter() - t0
                            self._report(entry, timings, found=True, password=res.password, found_by=ws.worker_id)
                            return 0
                        continue

                if self._found_password is None and allocator.exhausted():
                    if all(w.current_chunk is None for w in self._workers.values() if w.registered):
                        timings.total_runtime = time.perf_counter() - t0
                        self._report(entry, timings, found=False, password=None, found_by=None)
                        self._broadcast(stop_dict("SEARCH_COMPLETE"))
                        return 0

        finally:
            try:
                self._sel.close()
            except Exception:
                pass
            try:
                server.close()
            except Exception:
                pass
            for ws in list(self._workers.values()):
                try:
                    ws.sock.close()
                except Exception:
                    pass

    @staticmethod
    def _report(entry: ShadowEntry, timings: Timings, *, found: bool, password: Optional[str], found_by: Optional[str]) -> None:
        print("\n=== JOB INFO ===")
        print(f"Username:  {entry.username}")
        print(f"Algorithm: {entry.algo_name}")

        print("\n=== RESULTS ===")
        print(f"Password found: {found}")
        if found:
            print(f"Password:       {password}")
            print(f"Found by:       {found_by}")

        print("\n=== TIMING (seconds) ===")
        print(f"Parse time:         {timings.parse_time:.6f}")
        print(f"Dispatch overhead:  {timings.dispatch_overhead:.6f}")
        print(f"Total runtime:      {timings.total_runtime:.6f}")
        print(f"Assignments issued: {timings.assignments_issued}")
        print(f"Checkpoints recv:   {timings.checkpoints_received}")

        if timings.worker_runtimes:
            print("\n=== WORKER RUNTIMES ===")
            for worker_id, runtime in timings.worker_runtimes.items():
                print(f"{worker_id}: {runtime:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True, help="Path to shadow file")
    parser.add_argument("-u", required=True, help="Username to crack")
    parser.add_argument("-p", type=int, required=True, help="Port to listen on")
    parser.add_argument("-b", type=float, required=True, help="Heartbeat interval (seconds)")
    parser.add_argument("-c", type=int, required=True, help="Distributed chunk size (candidates per chunk)")
    parser.add_argument("-k", type=int, required=True, help="Checkpoint interval in candidate attempts")
    parser.add_argument("-l", type=int, default=3, help="Password length to brute-force (default: 3)")
    parser.add_argument("--min-workers", type=int, default=1, help="Wait until at least this many workers register before issuing chunks")
    args = parser.parse_args()

    app = ControllerApp(
        shadow_file=args.f,
        username=args.u,
        port=args.p,
        heartbeat_seconds=args.b,
        chunk_size=args.c,
        checkpoint_interval=args.k,
        length=args.l,
        min_workers=args.min_workers,
    )
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()