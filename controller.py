#!/usr/bin/env python3
from __future__ import annotations

import argparse
import selectors
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from common import (
    MessageIO,
    Register,
    Job,
    ChunkAssign,
    ChunkDone,
    Result,
    supported_charset_79,
    ProtocolError,
    PROTOCOL_VERSION,
    heartbeat_req_dict,
    no_more_work_dict,
    stop_dict,
)
from hashing import detect_algorithm_name


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


@dataclass
class WorkerState:
    sock: socket.socket
    addr: Tuple[str, int]
    worker_id: str
    threads: int
    total_tested: int = 0
    last_hb_print: float = 0.0
    connected_at: float = 0.0
    current_chunk_id: Optional[int] = None


class ChunkAllocator:
    def __init__(self, total_space: int, chunk_size: int) -> None:
        self.total_space = int(total_space)
        self.chunk_size = int(chunk_size)
        self.next_index = 0
        self.next_chunk_id = 1

    def claim(self) -> Optional[ChunkAssign]:
        if self.next_index >= self.total_space:
            return None
        start = self.next_index
        count = min(self.chunk_size, self.total_space - start)
        cid = self.next_chunk_id
        self.next_chunk_id += 1
        self.next_index += count
        return ChunkAssign(chunk_id=cid, start=start, count=count)


class ControllerApp:
    def __init__(
        self,
        shadow_file: str,
        username: str,
        port: int,
        heartbeat_seconds: float,
        chunk_size: int,
        length: int,
        min_workers: int,
    ) -> None:
        self.shadow_file = shadow_file
        self.username = username
        self.port = port
        self.heartbeat_seconds = heartbeat_seconds
        self.chunk_size = chunk_size
        self.length = length
        self.min_workers = min_workers

        self._workers: Dict[socket.socket, WorkerState] = {}
        self._sel = selectors.DefaultSelector()

        self._found_password: Optional[str] = None
        self._found_by: Optional[str] = None

    def _broadcast(self, obj: dict) -> None:
        for ws in list(self._workers.values()):
            try:
                MessageIO.send_msg(ws.sock, obj)
            except Exception:
                # best-effort; assignment fault model doesn't require recovery
                pass

    def _close_worker(self, sock: socket.socket) -> None:
        try:
            self._sel.unregister(sock)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        self._workers.pop(sock, None)

    def run(self) -> int:
        t0 = time.perf_counter()
        timings = Timings()

        # Parse shadow
        t_parse0 = time.perf_counter()
        entry = ShadowParser.parse_shadow_file(self.shadow_file, self.username)
        timings.parse_time = time.perf_counter() - t_parse0

        charset = supported_charset_79()
        total_space = (len(charset) ** self.length)
        allocator = ChunkAllocator(total_space=total_space, chunk_size=self.chunk_size)

        # Listen for workers
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", self.port))
        server.listen()
        server.setblocking(False)
        self._sel.register(server, selectors.EVENT_READ, data="ACCEPT")

        print(f"Controller listening on port {self.port} (protocol v{PROTOCOL_VERSION})")
        print(f"Target user: {entry.username}  Algo: {entry.algo_name}")
        print(f"Search space: |charset|={len(charset)} length={self.length} => total={total_space}")
        print(f"Distributed chunk_size={self.chunk_size}  heartbeat={self.heartbeat_seconds}s  min_workers={self.min_workers}")

        next_hb = time.perf_counter() + self.heartbeat_seconds

        try:
            while True:
                now = time.perf_counter()

                # Heartbeat tick
                if now >= next_hb:
                    for ws in list(self._workers.values()):
                        try:
                            MessageIO.send_msg(ws.sock, heartbeat_req_dict())
                        except Exception:
                            self._close_worker(ws.sock)
                    next_hb = now + self.heartbeat_seconds

                timeout = 0.25
                events = self._sel.select(timeout)

                for key, _mask in events:
                    if key.data == "ACCEPT":
                        conn, addr = server.accept()
                        conn.setblocking(False)
                        self._sel.register(conn, selectors.EVENT_READ, data="WORKER")
                        # WorkerState is filled after REGISTER
                        self._workers[conn] = WorkerState(sock=conn, addr=addr, worker_id="(unregistered)", threads=0, connected_at=time.perf_counter())
                        print(f"Worker connected from {addr}")
                        continue

                    sock = key.fileobj  # type: ignore
                    if sock not in self._workers:
                        continue
                    ws = self._workers[sock]

                    # read one message
                    try:
                        msg = MessageIO.recv_msg(sock)
                    except Exception:
                        self._close_worker(sock)
                        continue

                    mtype = msg.get("type")

                    if mtype == "REGISTER":
                        reg = Register.from_dict(msg)
                        ws.worker_id = reg.worker_id
                        ws.threads = reg.threads

                        # send job params
                        job = Job(
                            full_hash=entry.full_hash,
                            length=self.length,
                            charset=charset,
                            chunk_size=self.chunk_size,
                        )
                        MessageIO.send_msg(sock, job.to_dict())
                        print(f"Registered worker_id={ws.worker_id} threads={ws.threads} from {ws.addr}")
                        continue

                    if mtype == "HEARTBEAT_RESP":
                        # minimum required: delta_tested; we also accept optional fields
                        worker_id = str(msg.get("worker_id", ws.worker_id))
                        delta = int(msg.get("delta_tested", 0))
                        total = int(msg.get("total_tested", ws.total_tested + delta))
                        ws.total_tested = total
                        ws.current_chunk_id = msg.get("current_chunk_id", ws.current_chunk_id)

                        # print a compact progress line
                        print(f"[HB] {worker_id} delta={delta} total={total} active={int(msg.get('threads_active', 0))} chunk={ws.current_chunk_id}")
                        continue

                    # Work request / assignment (pull model)
                    if mtype == "WORK_REQUEST":
                        # don't issue new work if we're stopping
                        if self._found_password is not None:
                            MessageIO.send_msg(sock, stop_dict("FOUND_ELSEWHERE"))
                            continue

                        # Optionally wait for a minimum number of workers to join before distributing
                        if len([w for w in self._workers.values() if w.worker_id != "(unregistered)"]) < self.min_workers:
                            # Soft-wait: tell worker to retry (simple backoff)
                            MessageIO.send_msg(sock, {"type": "RETRY_LATER", "v": PROTOCOL_VERSION})
                            continue

                        assign = allocator.claim()
                        if assign is None:
                            MessageIO.send_msg(sock, no_more_work_dict())
                        else:
                            ws.current_chunk_id = assign.chunk_id
                            MessageIO.send_msg(sock, assign.to_dict())
                        continue

                    # Chunk completion notice (recommended)
                    if mtype == "CHUNK_DONE":
                        done = ChunkDone.from_dict(msg)

                        if done.found and done.password:
                            # winner!
                            self._found_password = done.password
                            self._found_by = ws.worker_id
                            print(f"FOUND by worker {ws.worker_id}: password='{done.password}' (chunk_id={done.chunk_id})")
                            self._broadcast(stop_dict("PASSWORD_FOUND"))
                            timings.total_runtime = time.perf_counter() - t0
                            self._report(entry, timings, found=True, password=done.password, found_by=ws.worker_id)
                            return 0

                        # otherwise just acknowledge internally (no need to respond)
                        continue

                    # Worker may still send RESULT for compatibility; treat as terminal.
                    if mtype == "RESULT":
                        res = Result.from_dict(msg)
                        if res.found and res.password:
                            self._found_password = res.password
                            self._found_by = ws.worker_id
                            print(f"FOUND (RESULT) by worker {ws.worker_id}: password='{res.password}'")
                            self._broadcast(stop_dict("PASSWORD_FOUND"))
                            timings.total_runtime = time.perf_counter() - t0
                            self._report(entry, timings, found=True, password=res.password, found_by=ws.worker_id)
                            return 0
                        continue

                    # ignore unknown messages (robustness)
                    continue

                # If all work has been issued and all workers have reported NO_MORE (or exited),
                # we can finish as "not found". We detect exhaustion by allocator and no active workers.
                if self._found_password is None and allocator.next_index >= allocator.total_space:
                    # If every registered worker is idle/exited, we're done.
                    if all(w.worker_id == "(unregistered)" for w in self._workers.values()):
                        continue
                    # best-effort finish condition: if no sockets left, or if workers are still connected they'll soon ask and get NO_MORE
                    if len(self._workers) == 0:
                        timings.total_runtime = time.perf_counter() - t0
                        self._report(entry, timings, found=False, password=None, found_by=None)
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
        print(f"Parse time:    {timings.parse_time:.6f}")
        print(f"Total runtime: {timings.total_runtime:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True, help="Path to shadow file")
    parser.add_argument("-u", required=True, help="Username to crack")
    parser.add_argument("-p", type=int, required=True, help="Port to listen on")
    parser.add_argument("-b", type=float, required=True, help="Heartbeat interval (seconds)")
    parser.add_argument("-k", type=int, required=True, help="Distributed chunk size (candidates per chunk)")
    parser.add_argument("-l", type=int, default=3, help="Password length to brute-force (default: 3)")
    parser.add_argument("--min-workers", type=int, default=1, help="Wait until at least this many workers register before issuing chunks")
    args = parser.parse_args()

    app = ControllerApp(args.f, args.u, args.p, args.b, args.k, args.l, args.min_workers)
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()
