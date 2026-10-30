from enum import IntEnum

class SecurityLabel(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def parse(cls, value):
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except (KeyError, ValueError, AttributeError):
            raise ValueError(f"Unknown security label: {value}")

    def __str__(self):
        return self.name

def highest_label(*labels):
    if not labels:
        raise ValueError("At least one label is required")
    return max(SecurityLabel.parse(x) for x in labels)
