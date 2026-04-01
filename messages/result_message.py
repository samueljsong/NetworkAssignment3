from __future__  import annotations
from dataclasses import dataclass
from typing      import Any, Dict, Optional
from interface   import Message
from common      import PROTOCOL_VERSION, ProtocolError

@dataclass(frozen=True)
class ResultMessage(Message):
    found        : bool
    password     : Optional[str]
    compute_time : float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type"         : "RESULT",
            "v"            : PROTOCOL_VERSION,
            "found"        : self.found,
            "password"     : self.password,
            "compute_time" : float(self.compute_time),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ResultMessage":
        if d.get("type") != "RESULT" or d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Expected RESULT message.")
        return ResultMessage(
            found        =bool(d["found"]),
            password     =d.get("password", None),
            compute_time =float(d["compute_time"]),
        )