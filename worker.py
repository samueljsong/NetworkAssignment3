#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import threading
import time
import uuid
from typing import Optional, Dict, Any

from common import (
    MessageIO,
    heartbeat_resp_dict,
    work_request_dict,
)
from cracking import ThreadedBruteForcer
from hashing import build_verifier
from messages import (
    RegisterMessage,
    JobMessage,
    ChunkAssignMessage,
    ChunkDoneMessage,
    WorkerDoneMessage,
    CheckpointResumeMessage,
)


class WorkerApp:
    def __init__(
        self,
        controller_host: str,
        port: int,
        threads: int,
        checkpoint_file: str,
        worker_id_file: str,
    ) -> None:
        self.controller_host = controller_host
        self.port = port
        self.threads = threads
        self.checkpoint_file = checkpoint_file
        self.worker_id_file = worker_id_file

        self.worker_id = self._load_or_create_worker_id()

        self._send_lock = threading.Lock()
        self._rx_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._stop_event = threading.Event()

        self._bruteforcer_lock = threading.Lock()
        self._bruteforcer: Optional[ThreadedBruteForcer] = None
        self._current_chunk_id: Optional[int] = None
        self._current_chunk_start: Optional[int] = None
        self._current_chunk_count: Optional[int] = None

        self._total_tested_global = 0
        self._last_hb_total_global = 0
        self._last_checkpoint_sent_total = 0

        self._job_signature: Optional[str] = None
        self._checkpoint_interval = 1000

    def _load_or_create_worker_id(self) -> str:
        if os.path.exists(self.worker_id_file):
            try:
                with open(self.worker_id_file, "r", encoding="utf-8") as f:
                    saved = f.read().strip()
                if saved:
                    return saved
            except Exception:
                pass

        new_id = str(uuid.uuid4())
        tmp = self.worker_id_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new_id)
        os.replace(tmp, self.worker_id_file)
        return new_id

    def _safe_send(self, sock: socket.socket, obj: dict) -> None:
        with self._send_lock:
            MessageIO.send_msg(sock, obj)

    def _get_progress(self) -> tuple[int, int, int, Optional[int]]:
        with self._bruteforcer_lock:
            bf = self._bruteforcer
            cid = self._current_chunk_id

        if bf is None:
            total = self._total_tested_global
            delta = total - self._last_hb_total_global
            self._last_hb_total_global = total
            return delta, total, 0, cid

        total_chunk = bf.get_total_tested()
        total = self._total_tested_global + total_chunk
        delta = total - self._last_hb_total_global
        self._last_hb_total_global = total
        active = bf.get_threads_active()
        return delta, total, active, cid

    def _load_checkpoint(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.checkpoint_file):
            return None
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_checkpoint(self, data: Dict[str, Any]) -> None:
        tmp = self.checkpoint_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self.checkpoint_file)

    def _clear_checkpoint(self) -> None:
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
        except Exception:
            pass

    def _build_checkpoint_payload(self) -> Optional[Dict[str, Any]]:
        with self._bruteforcer_lock:
            bf = self._bruteforcer
            chunk_id = self._current_chunk_id
            chunk_start = self._current_chunk_start
            chunk_count = self._current_chunk_count

        if bf is None or chunk_id is None or chunk_start is None or chunk_count is None:
            return None

        tested_in_chunk = bf.get_total_tested()
        resume_index = bf.get_resume_index()

        payload = {
            "type": "CHECKPOINT",
            "v": 2,
            "worker_id": self.worker_id,
            "chunk_id": chunk_id,
            "chunk_start": chunk_start,
            "chunk_count": chunk_count,
            "resume_index": resume_index,
            "tested_in_chunk": tested_in_chunk,
            "job_signature": self._job_signature,
            "timestamp": time.time(),
        }
        return payload

    def _checkpoint_loop(self, sock: socket.socket) -> None:
        while not self._stop_event.is_set():
            time.sleep(0.1)

            with self._bruteforcer_lock:
                bf = self._bruteforcer

            if bf is None:
                continue

            total = self._total_tested_global + bf.get_total_tested()
            if total - self._last_checkpoint_sent_total < self._checkpoint_interval:
                continue

            payload = self._build_checkpoint_payload()
            if payload is None:
                continue

            try:
                self._save_checkpoint(payload)
            except Exception:
                pass

            try:
                self._safe_send(sock, payload)
                self._last_checkpoint_sent_total = total
            except Exception:
                self._stop_event.set()
                return

    def _rx_loop(self, sock: socket.socket) -> None:
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
                self._stop_event.set()
                with self._bruteforcer_lock:
                    if self._bruteforcer is not None:
                        self._bruteforcer.stop()
                return

            if mtype in ("CHUNK_ASSIGN", "NO_MORE_WORK", "RETRY_LATER"):
                self._rx_queue.put(msg)
                continue

    def _maybe_resume_from_checkpoint(self, assign: ChunkAssignMessage) -> tuple[int, int]:
        start = assign.start
        count = assign.count
        end = start + count

        data = self._load_checkpoint()
        if not data:
            return start, count

        if data.get("job_signature") != self._job_signature:
            return start, count

        if data.get("worker_id") != self.worker_id:
            return start, count

        saved_resume = int(data.get("resume_index", start))
        saved_chunk_start = int(data.get("chunk_start", start))
        saved_chunk_count = int(data.get("chunk_count", count))
        saved_chunk_end = saved_chunk_start + saved_chunk_count

        if saved_resume < start or saved_resume > end:
            return start, count

        overlap_end = min(end, saved_chunk_end)
        if saved_resume >= overlap_end:
            return start, count

        new_start = saved_resume
        new_count = overlap_end - new_start
        return new_start, new_count

    def _send_resume_notice(
        self,
        sock: socket.socket,
        assign: ChunkAssignMessage,
        actual_start: int,
        actual_count: int,
    ) -> None:
        if actual_start <= assign.start:
            return

        msg = CheckpointResumeMessage(
            worker_id=self.worker_id,
            chunk_id=assign.chunk_id,
            assigned_start=assign.start,
            assigned_count=assign.count,
            resume_index=actual_start,
            remaining_count=actual_count,
        )

        self._safe_send(sock, msg.to_dict())

    def run(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print(f"Connecting to {self.controller_host}:{self.port} ...")
            sock.connect((self.controller_host, self.port))
            print("Connected to controller.")
        except Exception as e:
            print(f"Connection failed: {type(e).__name__}: {e}")
            try:
                sock.close()
            except Exception:
                pass
            return 1

        try:
            self._safe_send(sock, RegisterMessage(worker_id=self.worker_id, threads=self.threads).to_dict())

            job_msg = MessageIO.recv_msg(sock)
            job = JobMessage.from_dict(job_msg)

            self._checkpoint_interval = job.checkpoint_interval
            self._job_signature = f"{job.full_hash}|{job.length}|{job.charset}"
            verifier = build_verifier(job.full_hash)

            rx_thread = threading.Thread(target=self._rx_loop, args=(sock,), daemon=True)
            rx_thread.start()

            ckpt_thread = threading.Thread(target=self._checkpoint_loop, args=(sock,), daemon=True)
            ckpt_thread.start()

            worker_start = time.perf_counter()
            chunks_completed = 0
            sent_worker_done = False

            while not self._stop_event.is_set():
                self._safe_send(sock, work_request_dict(self.worker_id))

                try:
                    msg = self._rx_queue.get(timeout=5.0)
                except queue.Empty:
                    continue

                mtype = msg.get("type")

                if mtype == "RETRY_LATER":
                    time.sleep(0.5)
                    continue

                if mtype == "NO_MORE_WORK":
                    if not sent_worker_done:
                        sent_worker_done = True
                        worker_runtime = time.perf_counter() - worker_start
                        worker_done = WorkerDoneMessage(
                            worker_id=self.worker_id,
                            runtime_sec=worker_runtime,
                            chunks_completed=chunks_completed,
                            total_tested=self._total_tested_global,
                            found=False,
                        )
                        self._safe_send(sock, worker_done.to_dict())
                    return 0

                if mtype == "CHUNK_ASSIGN":
                    assign = ChunkAssignMessage.from_dict(msg)
                    actual_start, actual_count = self._maybe_resume_from_checkpoint(assign)

                    self._send_resume_notice(sock, assign, actual_start, actual_count)

                    with self._bruteforcer_lock:
                        self._current_chunk_id = assign.chunk_id
                        self._current_chunk_start = assign.start
                        self._current_chunk_count = assign.count
                        self._bruteforcer = ThreadedBruteForcer(
                            verifier=verifier,
                            charset=job.charset,
                            length=job.length,
                            threads=self.threads,
                            start_index=actual_start,
                            count=actual_count,
                            chunk_size=2000,
                            external_stop=self._stop_event,
                        )

                    t0 = time.perf_counter()
                    crack_res = self._bruteforcer.run()
                    t1 = time.perf_counter()

                    compute_time = t1 - t0
                    tested = crack_res.tried
                    self._total_tested_global += tested

                    chunk_done = ChunkDoneMessage(
                        chunk_id=assign.chunk_id,
                        tested=tested,
                        compute_time=compute_time,
                        found=crack_res.found,
                        password=crack_res.password,
                    )
                    self._safe_send(sock, chunk_done.to_dict())
                    chunks_completed += 1

                    with self._bruteforcer_lock:
                        self._bruteforcer = None
                        self._current_chunk_id = None
                        self._current_chunk_start = None
                        self._current_chunk_count = None

                    self._clear_checkpoint()

                    if crack_res.found and not sent_worker_done:
                        sent_worker_done = True
                        worker_runtime = time.perf_counter() - worker_start
                        worker_done = WorkerDoneMessage(
                            worker_id=self.worker_id,
                            runtime_sec=worker_runtime,
                            chunks_completed=chunks_completed,
                            total_tested=self._total_tested_global,
                            found=True,
                        )
                        self._safe_send(sock, worker_done.to_dict())
                        self._stop_event.set()
                        return 0

                    continue

            if not sent_worker_done:
                sent_worker_done = True
                worker_runtime = time.perf_counter() - worker_start
                worker_done = WorkerDoneMessage(
                    worker_id=self.worker_id,
                    runtime_sec=worker_runtime,
                    chunks_completed=chunks_completed,
                    total_tested=self._total_tested_global,
                    found=False,
                )
                try:
                    self._safe_send(sock, worker_done.to_dict())
                except Exception:
                    pass

            return 0

        finally:
            self._stop_event.set()
            try:
                sock.close()
            except Exception:
                pass


def main() -> None:
    import multiprocessing as mp

    mp.freeze_support()

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", required=True, help="Controller host/IP")
    parser.add_argument("-p", type=int, required=True, help="Controller port")
    parser.add_argument("-t", type=int, required=True, help="Worker thread count")
    parser.add_argument("--checkpoint-file", default="worker_checkpoint.json", help="Local checkpoint file path")
    parser.add_argument("--worker-id-file", default="worker_id.txt", help="Persistent worker ID file path")
    args = parser.parse_args()

    app = WorkerApp(
        args.c,
        args.p,
        args.t,
        args.checkpoint_file,
        args.worker_id_file,
    )
    raise SystemExit(app.run())