"""Padroes e utilitarios compartilhados entre analisadores.

Regex de IOCs, deteccao de bandeiras de CTF, extracao de strings e
decodificadores usados por varios modulos.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re

# ---------------------------------------------------------------- IOCs
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.I)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I
)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_BTC = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")

# Formatos comuns de bandeira de CTF.
RE_FLAG = re.compile(
    r"\b(?:flag|ctf|key|htb|thm|picoCTF|FLAG|CTF|KEY)\{[^}\r\n]{1,200}\}",
    re.I,
)

# Ruido a ignorar como "dominio" (extensoes de arquivo, etc.)
_DOMAIN_NOISE = re.compile(
    r"\.(png|jpg|jpeg|gif|css|js|html|php|txt|log|db|zip|exe|dll|json|xml)$", re.I
)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extrai IOCs de um texto, deduplicando e preservando ordem."""
    out: dict[str, list[str]] = {}

    def add(key: str, values) -> None:
        seen = out.setdefault(key, [])
        for v in values:
            v = v.strip().rstrip(".,);]'\"")
            if v and v not in seen:
                seen.append(v)

    add("ipv4", RE_IPV4.findall(text))
    add("url", RE_URL.findall(text))
    add("email", RE_EMAIL.findall(text))
    add("md5", RE_MD5.findall(text))
    add("sha1", RE_SHA1.findall(text))
    add("sha256", RE_SHA256.findall(text))
    add("btc", RE_BTC.findall(text))

    domains = [
        d for d in RE_DOMAIN.findall(text)
        if not _DOMAIN_NOISE.search(d) and not RE_IPV4.fullmatch(d)
    ]
    add("domain", domains)

    # Remove chaves vazias
    return {k: v for k, v in out.items() if v}


def find_flags(text: str) -> list[str]:
    return list(dict.fromkeys(RE_FLAG.findall(text)))


# ---------------------------------------------------------------- strings
def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Equivalente ao utilitario `strings` (ASCII imprimivel)."""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


def extract_strings_utf16(data: bytes, min_len: int = 4) -> list[str]:
    """Strings UTF-16LE (comuns em binarios/PowerShell do Windows)."""
    out, cur = [], bytearray()
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo <= 126:
            cur.append(lo)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur.clear()
        i += 2
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


# ---------------------------------------------------------------- decoders
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def try_base64(s: str) -> bytes | None:
    s = s.strip()
    if len(s) % 4 != 0 and "=" not in s:
        # tenta com padding
        s = s + "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
        if raw and _mostly_printable(raw):
            return raw
    except (binascii.Error, ValueError):
        pass
    return None


def try_hex(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s)
    if len(s) % 2 != 0 or len(s) < 8:
        return None
    try:
        raw = bytes.fromhex(s)
        if _mostly_printable(raw):
            return raw
    except ValueError:
        pass
    return None


def rot(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def atbash(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _mostly_printable(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    ok = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return ok / len(data) >= threshold


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def try_morse(s: str) -> str | None:
    if not re.fullmatch(r"[.\-/ ]+", s.strip()):
        return None
    words = s.strip().split("/")
    out = []
    for w in words:
        letters = [MORSE.get(t, "?") for t in w.split()]
        out.append("".join(letters))
    res = " ".join(out).strip()
    return res if res and "?" not in res else None


def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")
