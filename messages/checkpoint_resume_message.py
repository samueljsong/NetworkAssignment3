from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict
from interface import Message
from common import PROTOCOL_VERSION, ProtocolError


@dataclass(frozen=True)
class CheckpointResumeMessage(Message):
    worker_id: str
    chunk_id: int
    assigned_start: int
    assigned_count: int
    resume_index: int
    remaining_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "CHECKPOINT_RESUME",
            "v": PROTOCOL_VERSION,
            "worker_id": self.worker_id,
            "chunk_id": int(self.chunk_id),
            "assigned_start": int(self.assigned_start),
            "assigned_count": int(self.assigned_count),
            "resume_index": int(self.resume_index),
            "remaining_count": int(self.remaining_count),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "CheckpointResumeMessage":
        if d.get("type") != "CHECKPOINT_RESUME" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected CHECKPOINT_RESUME message.")
        return CheckpointResumeMessage(
            worker_id=str(d["worker_id"]),
            chunk_id=int(d["chunk_id"]),
            assigned_start=int(d["assigned_start"]),
            assigned_count=int(d["assigned_count"]),
            resume_index=int(d["resume_index"]),
            remaining_count=int(d["remaining_count"]),
        )