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


def work_request_dict(worker_id: str) -> Dict[str, Any]:
    return {"type": "WORK_REQUEST", "v": PROTOCOL_VERSION, "worker_id": worker_id}


def no_more_work_dict() -> Dict[str, Any]:
    return {"type": "NO_MORE_WORK", "v": PROTOCOL_VERSION}


def stop_dict(reason: str = "STOP") -> Dict[str, Any]:
    return {"type": "STOP", "v": PROTOCOL_VERSION, "reason": str(reason)}


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
