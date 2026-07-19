"""zugawatch — runtime call-chain anomaly monitor for MCP servers.

ZugaWatch sits between an MCP client (the agent) and a target MCP server. It
pins tool definitions on first connection to detect post-approval tampering
("rug pulls"), records the sequence of tool calls into a call-chain, and flags
anomalous execution patterns (e.g. read -> exfiltrate -> delete) that no
single static scanner can see.
"""

__version__ = "0.7.0"

from .pinning import ToolDef, ToolPin, PinStore, diff_pins
from .anomaly import CallEvent, CallChain, Finding, AnomalyEngine
from .grade import grade, Grade

__all__ = [
    "__version__",
    "ToolDef",
    "ToolPin",
    "PinStore",
    "diff_pins",
    "CallEvent",
    "CallChain",
    "Finding",
    "AnomalyEngine",
    "grade",
    "Grade",
]
