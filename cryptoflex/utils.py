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
        c_buf = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        ctypes.memset(ctypes.addressof(c_buf), 0, len(buffer))
    elif isinstance(buffer, memoryview):
        if not buffer.readonly:
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
