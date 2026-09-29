"""Sondas de rede de baixo nivel para o modo pentest (sem dependencias).

Implementa um cliente DNS minimo (UDP) e um GET SNMP v2c minimo, usados
pelo agente de reconhecimento. Tudo em cima da biblioteca padrao.

Uso etico e autorizado apenas.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import os
import socket
import struct

# ---------------------------------------------------------------- DNS
_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
              "AAAA": 28}


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def _read_name(data: bytes, off: int):
    labels, jumped, orig = [], False, off
    guard = 0
    while guard < 128:
        guard += 1
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
            off, jumped = ptr, True
            continue
        labels.append(data[off + 1:off + 1 + length].decode("latin-1"))
        off += 1 + length
    return ".".join(labels), (orig if jumped else off)


def dns_query(name: str, rtype: str, server: str = "8.8.8.8",
              timeout: float = 2.0) -> list[str]:
    """Consulta DNS simples via UDP. Retorna lista de respostas (strings)."""
    qt = _DNS_TYPES.get(rtype.upper())
    if not qt:
        return []
    tid = int.from_bytes(os.urandom(2), "big")
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1
    msg = header + _encode_name(name) + struct.pack(">HH", qt, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (server, 53))
        data, _ = s.recvfrom(4096)
    except OSError:
        return []
    finally:
        s.close()
    if len(data) < 12:
        return []
    ancount = struct.unpack_from(">H", data, 6)[0]
    # pula a pergunta
    _, off = _read_name(data, 12)
    off += 4
    out: list[str] = []
    for _ in range(ancount):
        try:
            _, off = _read_name(data, off)
            atype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, off)
            off += 10
            rdata = data[off:off + rdlen]
            out.append(_parse_rdata(atype, rdata, data, off))
            off += rdlen
        except (struct.error, IndexError):
            break
    return [x for x in out if x]


def _parse_rdata(atype: int, rdata: bytes, full: bytes, off: int) -> str:
    if atype == 1 and len(rdata) == 4:            # A
        return ".".join(map(str, rdata))
    if atype == 28 and len(rdata) == 16:          # AAAA
        return ":".join(f"{rdata[i]<<8|rdata[i+1]:x}" for i in range(0, 16, 2))
    if atype in (2, 5):                            # NS, CNAME
        return _read_name(full, off)[0]
    if atype == 15:                               # MX
        pref = struct.unpack_from(">H", rdata, 0)[0]
        host = _read_name(full, off + 2)[0]
        return f"{pref} {host}"
    if atype == 16:                               # TXT
        parts, i = [], 0
        while i < len(rdata):
            ln = rdata[i]
            parts.append(rdata[i + 1:i + 1 + ln].decode("latin-1"))
            i += 1 + ln
        return "".join(parts)
    return ""


# ---------------------------------------------------------------- SNMP (v2c GET)
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def _ber_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = []
    v = n
    while v:
        b.insert(0, v & 0xFF)
        v >>= 8
    if b[0] & 0x80:
        b.insert(0, 0)
    return _tlv(0x02, bytes(b))


def _ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            stack = []
            while p:
                stack.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body.extend(stack)
    return _tlv(0x06, bytes(body))


def snmp_get(host: str, community: str = "public",
             oid: str = "1.3.6.1.2.1.1.1.0", timeout: float = 2.0) -> str | None:
    """SNMP v2c GET de sysDescr. Retorna o valor (str) se responder, senao None."""
    reqid = int.from_bytes(os.urandom(3), "big")
    varbind = _tlv(0x30, _ber_oid(oid) + _tlv(0x05, b""))       # OID + NULL
    vblist = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _ber_int(reqid) + _ber_int(0) + _ber_int(0) + vblist)
    msg = _tlv(0x30, _ber_int(1) + _tlv(0x04, community.encode()) + pdu)  # v2c
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, 161))
        data, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    if not data or data[0] != 0x30:
        return None
    # extrai o maior trecho ASCII imprimivel como sysDescr (parse leve)
    best, cur = "", bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) > len(best):
                best = cur.decode("ascii", "replace")
            cur.clear()
    if len(cur) > len(best):
        best = cur.decode("ascii", "replace")
    return best or "(SNMP respondeu)"
