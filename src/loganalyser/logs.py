from __future__ import annotations

import gzip
import io
import tarfile
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO


def _read_text(stream: TextIO) -> Iterator[str]:
    yield from stream


def _read_file(path: Path, *, skip_sibling_copies: bool = False) -> Iterator[str]:
    if tarfile.is_tarfile(path):
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if skip_sibling_copies and (path.parent / member.name).is_file():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                is_gzip = extracted.read(2) == b"\x1f\x8b"
                extracted.seek(0)
                if is_gzip or member.name.endswith(".gz"):
                    with gzip.GzipFile(fileobj=extracted, mode="rb") as compressed:
                        with io.TextIOWrapper(
                            compressed, encoding="utf-8", errors="replace"
                        ) as stream:
                            yield from _read_text(stream)
                else:
                    with io.TextIOWrapper(extracted, encoding="utf-8", errors="replace") as stream:
                        yield from _read_text(stream)
        return

    with path.open("rb") as probe:
        is_gzip = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if is_gzip or path.suffix.lower() == ".gz" else open
    with opener(path, mode="rt", encoding="utf-8", errors="replace") as stream:
        yield from _read_text(stream)


def iter_log_lines(path: str | Path) -> Iterator[str]:
    """Yield lines from a log file or the files directly inside a directory."""
    source = Path(path)
    if source.is_file():
        yield from _read_file(source)
        return
    if not source.is_dir():
        raise FileNotFoundError(f"Log source does not exist: {source}")

    for child in sorted(source.iterdir()):
        if child.is_file():
            yield from _read_file(child, skip_sibling_copies=True)
