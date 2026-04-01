from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, ClassVar, Type, TypeVar

T = TypeVar("T", bound="Message")

class Message(ABC):
    TYPE: ClassVar[str]

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def from_dict(cls: Type[T], d: Dict[str, Any]) -> T:
        raise NotImplementedError