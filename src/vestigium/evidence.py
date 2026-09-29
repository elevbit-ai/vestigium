"""Ingestao e identificacao de evidencias.

Detecta o tipo de cada arquivo por magic bytes (com fallback por extensao),
calcula hashes e expoe metadados usados no roteamento entre analisadores.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# Assinaturas (magic bytes) -> rotulo logico de tipo.
_MAGIC: list[tuple[bytes, str]] = [
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"\x4d\x3c\xb2\xa1", "pcap"),      # nanosecond
    (b"SQLite format 3\x00", "sqlite"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),   # doc/xls/msg legado
    (b"-----BEGIN", "pem"),
]

_EXT_MAP = {
    ".pcap": "pcap", ".pcapng": "pcapng", ".cap": "pcap",
    ".db": "sqlite", ".sqlite": "sqlite", ".sqlite3": "sqlite", ".db3": "sqlite",
    ".log": "log", ".txt": "text",
    ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".bmp": "bmp",
    ".zip": "zip", ".rar": "rar",
    ".eml": "eml", ".msg": "msg",
    ".ps1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".js": "javascript", ".vbs": "vbscript", ".hta": "hta",
    ".doc": "ole", ".xls": "ole", ".docm": "zip", ".xlsm": "zip",
    ".exe": "pe", ".dll": "pe", ".bin": "binary",
    ".pem": "pem", ".key": "pem", ".crt": "pem",
    ".html": "html", ".htm": "html",
    ".json": "text", ".csv": "text", ".xml": "text",
}


def shannon_entropy(data: bytes) -> float:
    """Entropia de Shannon em bits/byte (0..8). >7.2 sugere cifrado/compactado."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Evidence:
    path: Path
    size: int
    kind: str
    sha256: str
    md5: str
    entropy: float
    head: bytes = b""                       # primeiros bytes (cache)
    text_sample: str = ""                    # amostra textual decodificada
    meta: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.path.name

    def read_bytes(self, limit: int | None = None) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read(limit) if limit else fh.read()

    def read_text(self, limit: int | None = None, errors: str = "replace") -> str:
        return self.read_bytes(limit).decode("utf-8", errors)


def _detect_kind(head: bytes, path: Path) -> str:
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            # Refinamento: PE/OLE/ZIP tem contexto por extensao
            if kind == "zip" and path.suffix.lower() in (".docm", ".xlsm", ".pptx", ".docx"):
                return "ooxml"
            return kind
    ext = _EXT_MAP.get(path.suffix.lower())
    if ext:
        return ext
    # Heuristica texto x binario
    if head and _looks_text(head):
        return "text"
    return "binary"


def _looks_text(sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return len(sample) == 0 or printable / len(sample) > 0.85


def load_evidence(path: str | os.PathLike) -> Evidence:
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as fh:
        head = fh.read(4096)
    # Hash em streaming (arquivos grandes)
    sha, md5 = hashlib.sha256(), hashlib.md5()
    ent_sample = bytearray()
    with open(p, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
            if len(ent_sample) < (1 << 20):
                ent_sample.extend(chunk[: (1 << 20) - len(ent_sample)])
    kind = _detect_kind(head, p)
    text_sample = ""
    if kind in ("text", "log", "html", "eml", "powershell", "batch",
                "javascript", "vbscript", "pem", "hta"):
        text_sample = head.decode("utf-8", "replace")
    return Evidence(
        path=p,
        size=size,
        kind=kind,
        sha256=sha.hexdigest(),
        md5=md5.hexdigest(),
        entropy=round(shannon_entropy(bytes(ent_sample)), 3),
        head=head,
        text_sample=text_sample,
    )


def collect(root: str | os.PathLike, max_bytes: int = 512 * 1024 * 1024) -> list[Evidence]:
    """Coleta recursivamente todos os arquivos sob `root` (ou um unico arquivo)."""
    root = Path(root)
    items: list[Evidence] = []
    paths: list[Path] = []
    if root.is_file():
        paths = [root]
    else:
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                paths.append(Path(dirpath) / f)
    for p in sorted(paths):
        try:
            if p.stat().st_size > max_bytes:
                continue
            items.append(load_evidence(p))
        except (OSError, PermissionError):
            continue
    return items
