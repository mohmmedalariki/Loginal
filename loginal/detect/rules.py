from dataclasses import dataclass, field
from typing import List, Callable, Iterator
import re
from ..normalize.schema import LogEvent

@dataclass
class Detection:
    rule_name: str
    severity: str
    event: LogEvent
    description: str
    tags: List[str] = field(default_factory=list)

class DetectionRule:
    def __init__(self, name: str, severity: str, condition: Callable[[LogEvent], bool], description: str = "", tags: List[str] = None):
        self.name = name
        self.severity = severity
        self.condition = condition
        self.description = description
        self.tags = tags or []

    def match(self, event: LogEvent) -> bool:
        return self.condition(event)

class DetectionEngine:
    def __init__(self):
        self.rules: List[DetectionRule] = []

    def load_defaults(self):
        """
        Load some default hardcoded rules.
        """
        # Rule 1: SSH Failed Password
        self.rules.append(DetectionRule(
            name="SSH Failed Login",
            severity="medium",
            condition=lambda e: "Failed password" in e.message,
            description="Detects failed SSH login attempts.",
            tags=["T1110", "Brute Force"]
        ))
        
        # Rule 2: Sudo usage
        self.rules.append(DetectionRule(
            name="Sudo Command",
            severity="low",
            condition=lambda e: ("COMM=" in e.message or "COMMAND=" in e.message) and "sudo" in e.original_data.get("raw_text", ""),
            description="Detects sudo command execution.",
            tags=["T1078", "Privilege Escalation"]
        ))

    def analyze(self, events: Iterator[LogEvent]) -> Iterator[Detection]:
        for event in events:
            for rule in self.rules:
                if rule.match(event):
                    yield Detection(
                        rule_name=rule.name,
                        severity=rule.severity,
                        event=event,
                        description=rule.description
                    )
