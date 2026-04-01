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
    CheckpointResumeMessage,
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
    total_cracking_time: float = 0.0
    dispatch_overhead: float = 0.0
    checkpoint_overhead: float = 0.0
    assignments_issued: int = 0
    checkpoints_received: int = 0
    heartbeats_received: int = 0
    worker_runtimes: Dict[str, float] = field(default_factory=dict)


@dataclass
class WorkerState:
    sock: socket.socket
    addr: Tuple[str, int]
    worker_id: str
    threads: int
    registered: bool = False
    connected_at: float = 0.0
    last_seen: float = 0.0
    total_tested: int = 0
    current_chunk: Optional[Tuple[int, int, int]] = None  # (chunk_id, start, count)
    current_resume_index: Optional[int] = None


class ChunkAllocator:
    def __init__(self, chunk_size: int) -> None:
        self.chunk_size = int(chunk_size)
        self.next_index = 0
        self.next_chunk_id = 1
        self.pending: Deque[Tuple[int, int, int]] = deque()  # (chunk_id, start, count)

    def requeue(self, chunk_id: int, start: int, count: int) -> None:
        if count <= 0:
            return
        self.pending.appendleft((int(chunk_id), int(start), int(count)))

    def claim(self) -> ChunkAssignMessage:
        if self.pending:
            chunk_id, start, count = self.pending.popleft()
            return ChunkAssignMessage(chunk_id=chunk_id, start=start, count=count)

        start = self.next_index
        count = self.chunk_size
        chunk_id = self.next_chunk_id

        self.next_index += count
        self.next_chunk_id += 1

        return ChunkAssignMessage(chunk_id=chunk_id, start=start, count=count)


class ControllerApp:
    def __init__(
        self,
        shadow_file: str,
        username: str,
        port: int,
        heartbeat_seconds: float,
        chunk_size: int,
        checkpoint_interval: int,
    ) -> None:
        self.shadow_file = shadow_file
        self.username = username
        self.port = port
        self.heartbeat_seconds = heartbeat_seconds
        self.chunk_size = chunk_size
        self.checkpoint_interval = checkpoint_interval

        self._workers: Dict[socket.socket, WorkerState] = {}
        self._sel = selectors.DefaultSelector()

        self._found_password: Optional[str] = None
        self._found_by: Optional[str] = None
        self._entry: Optional[ShadowEntry] = None

    def _broadcast(self, obj: dict) -> None:
        for ws in list(self._workers.values()):
            try:
                MessageIO.send_msg(ws.sock, obj)
            except Exception:
                pass

    def _safe_send(self, sock: socket.socket, obj: dict) -> bool:
        try:
            MessageIO.send_msg(sock, obj)
            return True
        except Exception:
            return False

    def _requeue_current_chunk(self, ws: WorkerState, allocator: ChunkAllocator) -> None:
        if ws.current_chunk is None:
            return

        chunk_id, start, count = ws.current_chunk
        resume = ws.current_resume_index if ws.current_resume_index is not None else start
        end = start + count
        resume = max(start, min(resume, end))
        remaining = end - resume

        if remaining > 0:
            allocator.requeue(chunk_id, resume, remaining)
            print(
                f"[RECOVER] requeued unfinished work from worker={ws.worker_id} "
                f"chunk_id={chunk_id} start={resume} count={remaining}"
            )

        ws.current_chunk = None
        ws.current_resume_index = None

    def _handle_disconnect(self, sock: socket.socket, allocator: ChunkAllocator) -> None:
        ws = self._workers.get(sock)
        if ws is not None:
            self._requeue_current_chunk(ws, allocator)

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
        now = time.time()
        timeout = max(2.0, self.heartbeat_seconds * 2.5)

        for sock, ws in list(self._workers.items()):
            if not ws.registered:
                continue
            if now - ws.last_seen > timeout:
                print(f"[TIMEOUT] worker {ws.worker_id} lost liveness")
                self._handle_disconnect(sock, allocator)

    @staticmethod
    def _report(
        entry: ShadowEntry,
        timings: Timings,
        *,
        found: bool,
        password: Optional[str],
        found_by: Optional[str],
    ) -> None:
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
        print(f"Checkpoint overhead: {timings.checkpoint_overhead:.6f}")
        print(f"Total runtime:      {timings.total_runtime:.6f}")
        print(f"Total cracking time: {timings.total_cracking_time:.6f}")
        print(f"Assignments issued: {timings.assignments_issued}")
        print(f"Checkpoints recv:   {timings.checkpoints_received}")
        print(f"Heartbeats recv:    {timings.heartbeats_received}")

        if timings.worker_runtimes:
            print("\n=== WORKER RUNTIMES ===")
            for worker_id, runtime in timings.worker_runtimes.items():
                print(f"{worker_id}: {runtime:.6f}")

    def run(self) -> int:
        t0 = time.perf_counter()
        timings = Timings()
        cracking_start_time: Optional[float] = None

        t_parse0 = time.perf_counter()
        self._entry = ShadowParser.parse_shadow_file(self.shadow_file, self.username)
        timings.parse_time = time.perf_counter() - t_parse0

        charset = supported_charset_79()
        allocator = ChunkAllocator(self.chunk_size)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", self.port))
        server.listen()
        server.setblocking(False)

        self._sel.register(server, selectors.EVENT_READ, data="ACCEPT")

        print("Controller running (UNBOUNDED SEARCH)")
        print(f"Target user: {self._entry.username}  Algo: {self._entry.algo_name}")
        print(f"heartbeat={self.heartbeat_seconds}s chunk_size={self.chunk_size} checkpoint={self.checkpoint_interval}")

        next_hb = time.time() + self.heartbeat_seconds

        try:
            while True:
                now = time.time()

                if now >= next_hb:
                    for ws in list(self._workers.values()):
                        if ws.registered:
                            if not self._safe_send(ws.sock, heartbeat_req_dict()):
                                self._handle_disconnect(ws.sock, allocator)
                    next_hb = now + self.heartbeat_seconds

                self._check_timeouts(allocator)

                events = self._sel.select(timeout=0.5)

                for key, _ in events:
                    if key.data == "ACCEPT":
                        conn, addr = server.accept()
                        conn.setblocking(False)
                        self._sel.register(conn, selectors.EVENT_READ, data="WORKER")
                        self._workers[conn] = WorkerState(
                            sock=conn,
                            addr=addr,
                            worker_id="",
                            threads=0,
                            registered=False,
                            connected_at=time.time(),
                            last_seen=time.time(),
                        )
                        print(f"Worker connected {addr}")
                        continue

                    sock = key.fileobj
                    ws = self._workers.get(sock)
                    if ws is None:
                        continue

                    try:
                        msg = MessageIO.recv_msg(sock)
                    except Exception:
                        self._handle_disconnect(sock, allocator)
                        continue

                    ws.last_seen = time.time()
                    mtype = msg.get("type")

                    if mtype == "REGISTER":
                        reg = RegisterMessage.from_dict(msg)
                        ws.worker_id = reg.worker_id
                        ws.threads = reg.threads
                        ws.registered = True

                        if cracking_start_time is None:
                            cracking_start_time = time.perf_counter()

                        t_dispatch0 = time.perf_counter()
                        job = JobMessage(
                            full_hash=self._entry.full_hash,
                            length=0,
                            charset=charset,
                            chunk_size=self.chunk_size,
                            heartbeat_seconds=self.heartbeat_seconds,
                            checkpoint_interval=self.checkpoint_interval,
                        )
                        ok = self._safe_send(sock, job.to_dict())
                        timings.dispatch_overhead += (time.perf_counter() - t_dispatch0)

                        if not ok:
                            self._handle_disconnect(sock, allocator)
                            continue

                        print(f"Registered worker_id={ws.worker_id} threads={ws.threads} from {ws.addr}")
                        continue

                    if mtype == "WORK_REQUEST":
                        if self._found_password is not None:
                            self._safe_send(sock, stop_dict("FOUND"))
                            continue

                        assign = allocator.claim()
                        ws.current_chunk = (assign.chunk_id, assign.start, assign.count)
                        ws.current_resume_index = assign.start
                        timings.assignments_issued += 1

                        print(
                            f"[ASSIGN] worker={ws.worker_id} "
                            f"chunk_id={assign.chunk_id} "
                            f"start={assign.start} "
                            f"count={assign.count}"
                        )

                        if not self._safe_send(sock, assign.to_dict()):
                            self._handle_disconnect(sock, allocator)
                        continue

                    if mtype == "CHECKPOINT":
                        t_ckpt0 = time.perf_counter()

                        timings.checkpoints_received += 1

                        if ws.current_chunk is not None:
                            chunk_id, start, count = ws.current_chunk
                            resume = int(msg.get("resume_index", start))
                            resume = max(start, min(resume, start + count))
                            ws.current_resume_index = resume

                        timings.checkpoint_overhead += (time.perf_counter() - t_ckpt0)

                        print(
                            f"[CKPT] worker={ws.worker_id} "
                            f"chunk={msg.get('chunk_id')} "
                            f"resume_index={msg.get('resume_index')}"
                        )
                        continue

                    if mtype == "CHECKPOINT_RESUME":
                        resume_msg = CheckpointResumeMessage.from_dict(msg)
                        print(
                            f"[RESUME] worker={resume_msg.worker_id} "
                            f"chunk_id={resume_msg.chunk_id} "
                            f"assigned_start={resume_msg.assigned_start} "
                            f"assigned_count={resume_msg.assigned_count} "
                            f"resume_index={resume_msg.resume_index} "
                            f"remaining_count={resume_msg.remaining_count}"
                        )
                        continue

                    if mtype == "HEARTBEAT_RESP":
                        timings.heartbeats_received += 1

                        ws.total_tested = int(msg.get("total_tested", ws.total_tested))

                        print(
                            f"[HB] {msg.get('worker_id')} "
                            f"delta={msg.get('delta_tested')} "
                            f"total={msg.get('total_tested')} "
                            f"active={msg.get('threads_active')} "
                            f"chunk={msg.get('current_chunk_id')}"
                        )
                        continue

                    if mtype == "CHUNK_DONE":
                        done = ChunkDoneMessage.from_dict(msg)

                        if ws.current_chunk is not None:
                            current_chunk_id, _, _ = ws.current_chunk
                            if current_chunk_id == done.chunk_id:
                                ws.current_chunk = None
                                ws.current_resume_index = None

                        if done.found and done.password:
                            self._found_password = done.password
                            self._found_by = ws.worker_id
                            print(f"PASSWORD FOUND by {ws.worker_id}: {done.password}")
                            self._broadcast(stop_dict("FOUND"))

                            now_perf = time.perf_counter()
                            timings.total_runtime = now_perf - t0
                            timings.total_cracking_time = 0.0 if cracking_start_time is None else (now_perf - cracking_start_time)

                            self._report(
                                self._entry,
                                timings,
                                found=True,
                                password=done.password,
                                found_by=ws.worker_id,
                            )
                            return 0

                        continue

                    if mtype == "WORKER_DONE":
                        wd = WorkerDoneMessage.from_dict(msg)
                        timings.worker_runtimes[wd.worker_id] = wd.runtime_sec
                        print(
                            f"[WORKER_DONE] worker={wd.worker_id} "
                            f"runtime={wd.runtime_sec:.4f}s "
                            f"chunks={wd.chunks_completed} "
                            f"tested={wd.total_tested}"
                        )
                        continue

                    if mtype == "RESULT":
                        res = ResultMessage.from_dict(msg)
                        if res.found and res.password:
                            self._found_password = res.password
                            self._found_by = ws.worker_id
                            print(f"PASSWORD FOUND: {res.password}")
                            self._broadcast(stop_dict("FOUND"))
                            
                            now_perf = time.perf_counter()
                            timings.total_runtime = now_perf - t0
                            timings.total_cracking_time = 0.0 if cracking_start_time is None else (now_perf - cracking_start_time)
                            
                            self._report(
                                self._entry,
                                timings,
                                found=True,
                                password=res.password,
                                found_by=ws.worker_id,
                            )
                            return 0
                        continue

        finally:
            if self._found_password is None and self._entry is not None:
                now_perf = time.perf_counter()
                timings.total_runtime = now_perf - t0
                timings.total_cracking_time = 0.0 if cracking_start_time is None else (now_perf - cracking_start_time)

                self._report(
                    self._entry,
                    timings,
                    found=False,
                    password=None,
                    found_by=None,
                )

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True, help="Path to shadow file")
    parser.add_argument("-u", required=True, help="Username to crack")
    parser.add_argument("-p", type=int, required=True, help="Port to listen on")
    parser.add_argument("-b", type=float, required=True, help="Heartbeat interval (seconds)")
    parser.add_argument("-c", type=int, required=True, help="Distributed chunk size")
    parser.add_argument("-k", type=int, required=True, help="Checkpoint interval in candidate attempts")
    args = parser.parse_args()

    app = ControllerApp(
        shadow_file=args.f,
        username=args.u,
        port=args.p,
        heartbeat_seconds=args.b,
        chunk_size=args.c,
        checkpoint_interval=args.k,
    )
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()