#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# Simple length-prefixed JSON protocol
PROTOCOL_VERSION = 2

class ProtocolError(Exception):
    pass


class MessageIO:
    @staticmethod
    def recv_msg(conn: socket.socket) -> Dict[str, Any]:
        header = MessageIO._recv_exact(conn, 4)
        length = int.from_bytes(header, "big")
        if length <= 0 or length > 100_000_000:
            raise ProtocolError(f"Invalid message length: {length}")

        data = MessageIO._recv_exact(conn, length)
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception as e:
            raise ProtocolError(f"Invalid JSON payload: {e}") from e
        if not isinstance(obj, dict):
            raise ProtocolError("Message must be a JSON object.")
        return obj

    @staticmethod
    def send_msg(conn: socket.socket, obj: Dict[str, Any]) -> None:
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        conn.sendall(len(payload).to_bytes(4, "big") + payload)

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ProtocolError("Connection closed unexpectedly.")
            buf += chunk
        return buf


# -----------------------------
# Message dataclasses / helpers
# -----------------------------

@dataclass(frozen=True)
class Register:
    worker_id: str
    threads: int

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "REGISTER", "v": PROTOCOL_VERSION, "worker_id": self.worker_id, "threads": int(self.threads)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Register":
        if d.get("type") != "REGISTER" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected REGISTER message.")
        return Register(worker_id=str(d["worker_id"]), threads=int(d["threads"]))


@dataclass(frozen=True)
class Job:
    full_hash: str
    length: int
    charset: str
    chunk_size: int  # number of candidates per distributed chunk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "JOB",
            "v": PROTOCOL_VERSION,
            "hash": self.full_hash,
            "length": int(self.length),
            "charset": self.charset,
            "chunk_size": int(self.chunk_size),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Job":
        if d.get("type") != "JOB" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected JOB message.")
        return Job(
            full_hash=str(d["hash"]),
            length=int(d["length"]),
            charset=str(d["charset"]),
            chunk_size=int(d["chunk_size"]),
        )


def work_request_dict(worker_id: str) -> Dict[str, Any]:
    return {"type": "WORK_REQUEST", "v": PROTOCOL_VERSION, "worker_id": worker_id}


@dataclass(frozen=True)
class ChunkAssign:
    chunk_id: int
    start: int          # global index start (inclusive)
    count: int          # number of candidates in this chunk

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "CHUNK_ASSIGN", "v": PROTOCOL_VERSION, "chunk_id": int(self.chunk_id), "start": int(self.start), "count": int(self.count)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ChunkAssign":
        if d.get("type") != "CHUNK_ASSIGN" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected CHUNK_ASSIGN message.")
        return ChunkAssign(chunk_id=int(d["chunk_id"]), start=int(d["start"]), count=int(d["count"]))


def no_more_work_dict() -> Dict[str, Any]:
    return {"type": "NO_MORE_WORK", "v": PROTOCOL_VERSION}


def stop_dict(reason: str = "STOP") -> Dict[str, Any]:
    return {"type": "STOP", "v": PROTOCOL_VERSION, "reason": str(reason)}


@dataclass(frozen=True)
class ChunkDone:
    chunk_id: int
    tested: int
    compute_time: float
    found: bool = False
    password: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "CHUNK_DONE",
            "v": PROTOCOL_VERSION,
            "chunk_id": int(self.chunk_id),
            "tested": int(self.tested),
            "compute_time": float(self.compute_time),
            "found": bool(self.found),
            "password": self.password,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ChunkDone":
        if d.get("type") != "CHUNK_DONE" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected CHUNK_DONE message.")
        return ChunkDone(
            chunk_id=int(d["chunk_id"]),
            tested=int(d.get("tested", 0)),
            compute_time=float(d.get("compute_time", 0.0)),
            found=bool(d.get("found", False)),
            password=d.get("password", None),
        )
    

@dataclass(frozen=True)
class WorkerDone:
    worker_id        : str
    runtime_sec      : float
    chunks_completed : int
    total_tested     : int
    found            : bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"             : "WORKER_DONE",
            "v"                : PROTOCOL_VERSION,
            "worker_id"        : self.worker_id,
            "runtime_sec"      : float(self.runtime_sec),
            "chunks_completed" : int(self.chunks_completed),
            "total_tested"     : int(self.total_tested),
            "found"            : bool(self.found),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "WorkerDone":
        if d.get("type") != "WORKER_DONE" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected WORKER_DONE message.")
        return WorkerDone(
            worker_id        = str(d.get("worker_id", "")),
            runtime_sec      = float(d.get("runtime_sec", 0.0)),
            chunks_completed = int(d.get("chunks_completed", 0)),
            total_tested     = int(d.get("total_tested", 0)),
            found            = bool(d.get("found", False)),
        )


@dataclass(frozen=True)
class Result:
    found: bool
    password: Optional[str]
    compute_time: float

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "RESULT", "v": PROTOCOL_VERSION, "found": self.found, "password": self.password, "compute_time": float(self.compute_time)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Result":
        if d.get("type") != "RESULT" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected RESULT message.")
        return Result(found=bool(d["found"]), password=d.get("password", None), compute_time=float(d["compute_time"]))


# ---- Heartbeat messages ----

def heartbeat_req_dict() -> Dict[str, Any]:
    return {"type": "HEARTBEAT_REQ", "v": PROTOCOL_VERSION}


def heartbeat_resp_dict(
    worker_id: str,
    delta_tested: int,
    total_tested: int,
    threads_active: int,
    current_chunk_id: Optional[int],
) -> Dict[str, Any]:
    return {
        "type": "HEARTBEAT_RESP",
        "v": PROTOCOL_VERSION,
        "worker_id": worker_id,
        "delta_tested": int(delta_tested),
        "total_tested": int(total_tested),
        "threads_active": int(threads_active),
        "current_chunk_id": current_chunk_id,
    }


def supported_charset_79() -> str:
    return (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:',.<>/?"
    )
