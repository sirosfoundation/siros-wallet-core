"""The files the scripts in this directory open from their command line.

A script opens a file only inside the repository that holds this directory.
Each path is canonicalised first, symbolic links and `..` resolved, and the
canonical path must start with the repository root followed by a separator.
The script then opens that canonical path.
"""
from __future__ import annotations

import os
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parent.parent


class PathRefused(Exception):
    """A path a script refuses; the message names the path and the reason."""


def _inside_repository(canonical: str, argument: str) -> Path:
    if not canonical.startswith(str(REPOSITORY_ROOT) + os.sep):
        raise PathRefused(f"{argument}: {canonical} lies outside the repository {REPOSITORY_ROOT}")
    return Path(canonical)


def _named(path: Path, argument: str, suffix: str) -> Path:
    if path.suffix != suffix:
        raise PathRefused(f"{argument}: the name does not end in {suffix}")
    return path


def existing_file(argument: str, suffix: str) -> Path:
    """The regular file `argument` names, inside the repository, named `*suffix`."""
    try:
        canonical = str(Path(argument).resolve(strict=True))
    except (OSError, RuntimeError) as error:
        raise PathRefused(f"{argument}: {error}") from error
    path = _inside_repository(canonical, argument)
    if not path.is_file():
        raise PathRefused(f"{argument}: not a regular file")
    return _named(path, argument, suffix)


def new_file(argument: str, suffix: str) -> Path:
    """Where to write `argument`: a path inside the repository, named `*suffix`,
    in a directory that exists. A regular file already there is replaced."""
    try:
        canonical = str(Path(argument).resolve())
    except (OSError, RuntimeError) as error:
        raise PathRefused(f"{argument}: {error}") from error
    path = _inside_repository(canonical, argument)
    if not path.parent.is_dir():
        raise PathRefused(f"{argument}: the directory {path.parent} does not exist")
    if path.exists() and not path.is_file():
        raise PathRefused(f"{argument}: exists and is not a regular file")
    return _named(path, argument, suffix)
