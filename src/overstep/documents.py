"""Reading the files a run is configured from.

Every command starts by reading a file somebody typed the path to: a matrix, an
OpenAPI spec, a HAR capture, a waivers list, a drift baseline. Two things go
wrong with those far more often than anything the validators look for — the path
is not there, and the YAML is indented wrong — and both used to surface as a raw
traceback, because the ``open()``/``parse`` pair sat outside the ``try`` that
wrapped the rest of the loading.

That is the wrong shape for the most common failure in the tool. The parsers
already know exactly what happened and where: PyYAML carries a problem mark with
a line and column, and :mod:`json` carries the same on its decode error. The
traceback did not hide that information so much as bury it under forty lines of
overstep's own source, which is noise in a terminal and worse in a CI log.

So the reading is centralized here, and every failure to obtain a document comes
back as one :class:`DocumentError` that names the file, its role in the run, and
the position the parser stopped at. :class:`DocumentError` subclasses
``ValueError`` so that callers already catching ``(OSError, ValueError)`` around
a loader keep working unchanged.

Nothing here validates *content* — a well-formed YAML file that is not a matrix
is this module's success and :mod:`overstep.matrix`'s problem.
"""
from __future__ import annotations

import json
from typing import Any

import yaml


class DocumentError(ValueError):
    """Raised when a configuration file cannot be read or parsed.

    Subclasses ``ValueError`` rather than ``OSError`` because by the time it
    reaches a caller the distinction between "missing" and "malformed" no longer
    changes what anyone does about it: the message says which, and either way
    the run cannot start.
    """


def _describe_os_error(exc: OSError, path: str, what: str) -> str:
    """Say what is wrong with the path in the terms the user typed it in.

    The three cases split out here are the ones with an obvious fix — the path
    is wrong, it points at a directory, or it cannot be read — and naming the
    fix is worth more than the errno that implies it.
    """
    if isinstance(exc, FileNotFoundError):
        return f"{what} '{path}' does not exist"
    if isinstance(exc, IsADirectoryError):
        return f"{what} '{path}' is a directory, not a file"
    if isinstance(exc, PermissionError):
        return f"{what} '{path}' is not readable (permission denied)"
    return f"could not read {what} '{path}': {exc.strerror or exc}"


def _read_text(path: str, what: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise DocumentError(_describe_os_error(exc, path, what)) from exc
    except UnicodeDecodeError as exc:
        # A binary file — a gzipped HAR, a PDF of the spec, an image. The codec
        # error names a byte offset, which tells the user nothing useful.
        raise DocumentError(
            f"{what} '{path}' is not UTF-8 text — it looks like a binary file"
        ) from exc


def _at(line: int, column: int) -> str:
    """Format a parser position for humans, who count from one."""
    return f"line {line}, column {column}"


def read_yaml(path: str, what: str = "file") -> Any:
    """Parse a YAML file, or raise :class:`DocumentError` explaining why not.

    An empty file yields ``None``, exactly as ``yaml.safe_load`` does; callers
    decide whether that is a valid document for them.
    """
    text = _read_text(path, what)
    try:
        return yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        # The mark is what makes this actionable, so it leads. Both marks are
        # 0-indexed; editors are not.
        mark = exc.problem_mark
        where = f" ({_at(mark.line + 1, mark.column + 1)})" if mark else ""
        problem = exc.problem or "invalid YAML"
        raise DocumentError(f"{what} '{path}' is not valid YAML: {problem}{where}") from exc
    except yaml.YAMLError as exc:
        raise DocumentError(f"{what} '{path}' is not valid YAML: {exc}") from exc


def read_json(path: str, what: str = "file") -> Any:
    """Parse a JSON file, or raise :class:`DocumentError` explaining why not.

    An empty file is a parse error in JSON, and is reported as one — unlike
    YAML, there is no reading of it that produces a document.
    """
    text = _read_text(path, what)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise DocumentError(
            f"{what} '{path}' is not valid JSON: {exc.msg} ({_at(exc.lineno, exc.colno)})"
        ) from exc
