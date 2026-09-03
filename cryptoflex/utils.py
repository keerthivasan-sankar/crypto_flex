"""
cryptoflex.utils
=================

Local memory security utilities.
"""

from __future__ import annotations

import ctypes


def zeroize(buffer: bytearray | memoryview) -> None:
    """Overwrites a mutable bytearray or memoryview buffer with zeros in-place
    to minimize sensitive key material retention in memory.
    """
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    elif isinstance(buffer, memoryview):
        if not buffer.readonly:
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
