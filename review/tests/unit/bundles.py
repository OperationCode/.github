"""Shared pieces for hand-built bundle envelopes in the unit tests."""


def size_record(status: str = "ok", **over) -> dict:
    """A schema-valid `payload.size` record (spec "Size-limit raise command")."""
    skipped = status == "skipped-size"
    record = {
        "estimated_tokens": 300_000 if skipped else 1_000,
        "limit_tokens": 200_000,
        "base_limit_tokens": 200_000,
        "multiplier": 1,
        "mode": "skipped" if skipped else "full",
        "commands_read": True,
        "raise": None,
        "rejected_commands": [],
    }
    if skipped:
        record["reason"] = "too large for automatic review: estimated 300000 tokens with no patches, limit 200000"
    record.update(over)
    return record
