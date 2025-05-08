

"""
secbot.utils.retry
~~~~~~~~~~~~~~~~~~

Tiny *retry* decorator with exponential back‑off & jitter, intended for
network‑bound helper functions inside SecBot (e.g. RSS fetchers or
ASEC HTML downloads).

Example
-------
>>> from secbot.utils.retry import retry
>>> @retry(attempts=3, backoff=2.0)
... def flaky():
...     ...
"""

from __future__ import annotations

import random
import time
from functools import wraps
from typing import Callable, TypeVar

T = TypeVar("T")


def retry(
    *,
    attempts: int = 5,
    delay: float = 1.0,
    backoff: float = 2.0,
    jitter: float = 0.2,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that retries a function call with exponential back‑off.

    Parameters
    ----------
    attempts:
        Total number of attempts (including the first one).
    delay:
        Initial delay in seconds before the first retry.
    backoff:
        Multiplicative factor for the delay after each failure.
    jitter:
        Random ±jitter*delay offset to avoid thundering‑herd.
    exceptions:
        Tuple of exception classes that should trigger a retry.

    Returns
    -------
    Callable
        Wrapped function that will retry on configured exceptions.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:  # type: ignore[override]
            _attempt = 0
            _delay = delay
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    _attempt += 1
                    if _attempt >= attempts:
                        raise
                    sleep_for = _delay + random.uniform(-jitter, jitter) * _delay
                    time.sleep(max(sleep_for, 0))
                    _delay *= backoff

        return wrapper

    return decorator