"""LexTier error codes — parity with src/core/errors.ts."""


class LexError(Exception):
    """Protocol error with a stable code."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


def err(code: str, message: str | None = None) -> LexError:
    return LexError(code, message)
