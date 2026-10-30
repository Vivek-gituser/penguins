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
        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                raise ValueError(f"Unknown security label: {value}")
        try:
            return cls[str(value).strip().upper()]
        except (KeyError, ValueError, AttributeError):
            raise ValueError(f"Unknown security label: {value}")

def highest_label(*labels):
    # Accept either highest_label(label1, label2) or highest_label([label1, label2]).
    if len(labels) == 1 and not isinstance(labels[0], (str, SecurityLabel, int)):
        try:
            labels = tuple(labels[0])
        except TypeError:
            pass

    if not labels:
        raise ValueError("At least one security label is required")

    return max(SecurityLabel.parse(label) for label in labels)
