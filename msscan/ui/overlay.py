"""Alternate-screen overlay and cross-platform raw key reader."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Generator

from rich.console import Console, RenderableType

# ---------------------------------------------------------------------------
# Windows VT processing setup
# ---------------------------------------------------------------------------

def _enable_windows_vt() -> None:
    """Enable ANSI / Virtual Terminal processing on Windows."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass  # best-effort


_enable_windows_vt()

# ---------------------------------------------------------------------------
# Alternate screen context manager
# ---------------------------------------------------------------------------

@contextmanager
def alternate_screen() -> Generator[None, None, None]:
    """Enter the terminal alternate screen buffer; restore on exit."""
    stdout = sys.stdout
    try:
        stdout.write("\033[?1049h")  # enter alternate screen
        stdout.write("\033[?25l")    # hide cursor
        stdout.flush()
        yield
    finally:
        stdout.write("\033[?25h")    # show cursor
        stdout.write("\033[?1049l")  # leave alternate screen
        stdout.flush()


def _clear_screen() -> None:
    """Clear the alternate screen and move cursor to top-left."""
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.flush()

# ---------------------------------------------------------------------------
# Cross-platform raw key reader
# ---------------------------------------------------------------------------

def read_key() -> str:
    """Read a single keypress and return a normalized name.

    Returns one of:
        "UP", "DOWN", "LEFT", "RIGHT",
        "SPACE", "ENTER", "ESC", "TAB",
        "q", "a", "v",
        "1"-"5",
        or the literal character.
    """
    if os.name == "nt":
        return _read_key_windows()
    return _read_key_unix()


def _read_key_windows() -> str:
    import msvcrt
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        # Special key — read the second byte
        ch2 = msvcrt.getwch()
        return {
            "H": "UP",
            "P": "DOWN",
            "K": "LEFT",
            "M": "RIGHT",
        }.get(ch2, "")
    if ch == "\x03":
        raise KeyboardInterrupt
    if ch == "\r":
        return "ENTER"
    if ch == "\x1b":
        return "ESC"
    if ch == " ":
        return "SPACE"
    if ch == "\t":
        return "TAB"
    return ch


def _read_key_unix() -> str:
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x1b":
            # Could be ESC or start of escape sequence
            ch2 = sys.stdin.read(1)
            if ch2 == "[":
                ch3 = sys.stdin.read(1)
                return {
                    "A": "UP",
                    "B": "DOWN",
                    "C": "RIGHT",
                    "D": "LEFT",
                }.get(ch3, "")
            return "ESC"
        if ch == "\r" or ch == "\n":
            return "ENTER"
        if ch == " ":
            return "SPACE"
        if ch == "\t":
            return "TAB"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

# ---------------------------------------------------------------------------
# Overlay rendering helpers
# ---------------------------------------------------------------------------

def render_overlay(
    console: Console,
    renderable: RenderableType,
    footer: str = "Press [bold]q[/bold] or [bold]ESC[/bold] to close",
) -> None:
    """Clear the alternate screen and render content with a footer."""
    _clear_screen()

    # Use capture to build the full output, then write at once to reduce flicker
    with console.capture() as capture:
        console.print()
        console.print(renderable, justify="center")
        console.print()
        console.print(f"[dim]{footer}[/dim]", justify="center")

    sys.stdout.write(capture.get())
    sys.stdout.flush()


def show_overlay(
    console: Console,
    renderable: RenderableType,
    footer: str = "Press [bold]q[/bold] or [bold]ESC[/bold] to close",
) -> None:
    """Show a renderable in the alternate screen; wait for q/ESC to close."""
    min_rows = 20
    if console.size.height < min_rows:
        # Terminal too small — fall back to inline rendering
        console.print()
        console.print(renderable)
        console.print()
        return

    with alternate_screen():
        render_overlay(console, renderable, footer)
        while True:
            key = read_key()
            if key in ("q", "ESC"):
                break
