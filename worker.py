#!/usr/bin/env python3
from __future__ import annotations

import argparse
import queue
import socket
import threading
import time
import uuid
from typing import Optional, Dict, Any

from common import (
    MessageIO,
    Register,
    Job,
    ChunkAssign,
    ChunkDone,
    PROTOCOL_VERSION,
    ProtocolError,
    heartbeat_resp_dict,
    work_request_dict,
)
from cracking import ThreadedBruteForcer
from hashing import build_verifier


class WorkerApp:
    def __init__(self, controller_host: str, port: int, threads: int) -> None:
        self.controller_host = controller_host
        self.port = port
        self.threads = threads

        self.worker_id = str(uuid.uuid4())

        self._send_lock = threading.Lock()

        # Single receiver thread -> queues messages for main loop
        self._rx_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        self._stop_event = threading.Event()  # global stop (STOP from controller or local found)

        self._bruteforcer_lock = threading.Lock()
        self._bruteforcer: Optional[ThreadedBruteForcer] = None
        self._current_chunk_id: Optional[int] = None
        self._total_tested_global = 0
        self._last_hb_total_global = 0

    def _safe_send(self, sock: socket.socket, obj: dict) -> None:
        with self._send_lock:
            MessageIO.send_msg(sock, obj)

    def _get_progress(self) -> tuple[int, int, int, Optional[int]]:
        # returns (delta, total, threads_active, current_chunk_id)
        with self._bruteforcer_lock:
            bf = self._bruteforcer
            cid = self._current_chunk_id

        if bf is None:
            total = self._total_tested_global
            delta = total - self._last_hb_total_global
            self._last_hb_total_global = total
            return delta, total, 0, cid

        total_chunk = bf.get_total_tested()
        # global total = previous chunks + current chunk
        total = self._total_tested_global + total_chunk
        delta = total - self._last_hb_total_global
        self._last_hb_total_global = total
        active = bf.get_threads_active()
        return delta, total, active, cid

    def _rx_loop(self, sock: socket.socket) -> None:
        # read all inbound messages and dispatch
        sock.settimeout(1.0)
        while not self._stop_event.is_set():
            try:
                msg = MessageIO.recv_msg(sock)
            except socket.timeout:
                continue
            except Exception:
                self._stop_event.set()
                return

            mtype = msg.get("type")

            if mtype == "HEARTBEAT_REQ":
                delta, total, active, cid = self._get_progress()
                resp = heartbeat_resp_dict(
                    worker_id=self.worker_id,
                    delta_tested=delta,
                    total_tested=total,
                    threads_active=active,
                    current_chunk_id=cid,
                )
                try:
                    self._safe_send(sock, resp)
                except Exception:
                    self._stop_event.set()
                    return
                continue

            if mtype == "STOP":
                # global stop from controller
                self._stop_event.set()
                with self._bruteforcer_lock:
                    if self._bruteforcer is not None:
                        self._bruteforcer.stop()
                return

            # Forward work-related messages to main loop
            if mtype in ("CHUNK_ASSIGN", "NO_MORE_WORK", "RETRY_LATER"):
                self._rx_queue.put(msg)
                continue

            # ignore unknown messages

    def run(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_host, self.port))

        try:
            # Register
            self._safe_send(sock, Register(worker_id=self.worker_id, threads=self.threads).to_dict())

            # Receive JOB (main thread reads once before rx thread starts)
            job_msg = MessageIO.recv_msg(sock)
            job = Job.from_dict(job_msg)

            verifier = build_verifier(job.full_hash)

            # Start receiver thread (heartbeats + STOP + work replies)
            rx_thread = threading.Thread(target=self._rx_loop, args=(sock,), daemon=True)
            rx_thread.start()

            while not self._stop_event.is_set():
                # Ask for a chunk (pull model)
                self._safe_send(sock, work_request_dict(self.worker_id))

                # Wait for controller response
                try:
                    msg = self._rx_queue.get(timeout=5.0)
                except queue.Empty:
                    continue

                mtype = msg.get("type")

                if mtype == "RETRY_LATER":
                    time.sleep(0.5)
                    continue

                if mtype == "NO_MORE_WORK":
                    # nothing left; exit cleanly
                    return 0

                if mtype == "CHUNK_ASSIGN":
                    assign = ChunkAssign.from_dict(msg)

                    # Run brute force on this chunk
                    with self._bruteforcer_lock:
                        self._current_chunk_id = assign.chunk_id
                        self._bruteforcer = ThreadedBruteForcer(
                            verifier=verifier,
                            charset=job.charset,
                            length=job.length,
                            threads=self.threads,
                            start_index=assign.start,
                            count=assign.count,
                            chunk_size=2000,
                            external_stop=self._stop_event,
                        )

                    t0 = time.perf_counter()
                    crack_res = self._bruteforcer.run()
                    t1 = time.perf_counter()

                    compute_time = t1 - t0
                    tested = crack_res.tried

                    # Update global tested baseline (chunk finished)
                    self._total_tested_global += tested

                    # Report chunk completion (recommended in the spec)
                    done = ChunkDone(
                        chunk_id=assign.chunk_id,
                        tested=tested,
                        compute_time=compute_time,
                        found=crack_res.found,
                        password=crack_res.password,
                    )
                    self._safe_send(sock, done.to_dict())

                    # Clear current bruteforcer reference
                    with self._bruteforcer_lock:
                        self._bruteforcer = None
                        self._current_chunk_id = None

                    if crack_res.found:
                        # Local winner. Controller will broadcast STOP to others.
                        self._stop_event.set()
                        return 0

                    # otherwise loop and request next chunk
                    continue

            return 0

        finally:
            self._stop_event.set()
            try:
                sock.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", required=True, help="Controller host/IP")
    parser.add_argument("-p", type=int, required=True, help="Controller port")
    parser.add_argument("-t", type=int, required=True, help="Worker thread count")
    args = parser.parse_args()

    app = WorkerApp(args.c, args.p, args.t)
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()
