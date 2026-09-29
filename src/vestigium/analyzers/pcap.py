"""Analisador PCAP: dissecacao de capturas de rede sem dependencias externas.

Parser proprio para pcap (classico) e pcapng. Decodifica Ethernet/IPv4/
TCP/UDP, extrai consultas DNS, requisicoes HTTP (host/URL/user-agent),
credenciais em texto claro (HTTP Basic, FTP/POP/IMAP), procura bandeiras
em payloads e detecta indicios de beaconing (C2).

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import base64
import struct
from collections import Counter, defaultdict

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context


class Packet:
    __slots__ = ("ts", "src", "dst", "sport", "dport", "proto", "payload")

    def __init__(self, ts, src, dst, sport, dport, proto, payload):
        self.ts = ts
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.proto = proto
        self.payload = payload


class PcapAnalyzer(Analyzer):
    name = "pcap"
    category = "pcap"
    handles = ("pcap", "pcapng")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        data = ev.read_bytes()
        try:
            if ev.kind == "pcapng":
                pkts = list(self._parse_pcapng(data))
            else:
                pkts = list(self._parse_pcap(data))
        except Exception as exc:  # parser robusto: nunca aborta a varredura
            return [Finding(
                analyzer=self.name, category="pcap",
                title="Falha ao decodificar a captura",
                severity=Severity.INFO, source=str(ev.path),
                description=f"Parser interrompido: {exc}",
            )]

        findings: list[Finding] = []
        findings.append(self._overview(ev, pkts))
        findings += self._dns(ev, pkts)
        findings += self._http(ev, pkts)
        findings += self._cleartext_creds(ev, pkts)
        findings += self._flags_in_payload(ev, pkts)
        findings += self._beaconing(ev, pkts)
        return [f for f in findings if f]

    # -------------------------------------------------- parsers
    def _parse_pcap(self, data: bytes):
        magic = data[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4",):
            endian = ">"
        else:
            endian = "<"
        linktype = struct.unpack_from(endian + "I", data, 20)[0]
        off = 24
        n = len(data)
        while off + 16 <= n:
            ts_sec, ts_usec, caplen, _orig = struct.unpack_from(endian + "IIII", data, off)
            off += 16
            frame = data[off: off + caplen]
            off += caplen
            pkt = self._decode_frame(frame, linktype, ts_sec + ts_usec / 1e6)
            if pkt:
                yield pkt

    def _parse_pcapng(self, data: bytes):
        off = 0
        n = len(data)
        endian = "<"
        linktype = 1
        while off + 12 <= n:
            btype, blen = struct.unpack_from(endian + "II", data, off)
            if btype == 0x0A0D0D0A:  # section header
                bom = struct.unpack_from("<I", data, off + 8)[0]
                endian = "<" if bom == 0x1A2B3C4D else ">"
                btype, blen = struct.unpack_from(endian + "II", data, off)
            if blen < 12 or off + blen > n:
                break
            body = data[off + 8: off + blen - 4]
            if btype == 0x00000001:  # interface description
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
            elif btype == 0x00000006:  # enhanced packet
                caplen = struct.unpack_from(endian + "I", body, 12)[0]
                frame = body[20: 20 + caplen]
                ts_hi, ts_lo = struct.unpack_from(endian + "II", body, 4)
                ts = ((ts_hi << 32) | ts_lo) / 1e6
                pkt = self._decode_frame(frame, linktype, ts)
                if pkt:
                    yield pkt
            elif btype == 0x00000003:  # simple packet
                frame = body[4:]
                pkt = self._decode_frame(frame, linktype, 0.0)
                if pkt:
                    yield pkt
            off += blen

    def _decode_frame(self, frame: bytes, linktype: int, ts: float):
        try:
            if linktype == 1:              # Ethernet
                if len(frame) < 14:
                    return None
                etype = struct.unpack_from(">H", frame, 12)[0]
                l3 = frame[14:]
                if etype != 0x0800:        # somente IPv4
                    return None
            elif linktype == 101:          # raw IP
                l3 = frame
            else:
                # tenta pular cabecalho de 2 bytes (linux cooked) ou desiste
                l3 = frame[16:] if linktype == 113 else frame
            if len(l3) < 20 or (l3[0] >> 4) != 4:
                return None
            ihl = (l3[0] & 0x0F) * 4
            proto = l3[9]
            src = ".".join(map(str, l3[12:16]))
            dst = ".".join(map(str, l3[16:20]))
            l4 = l3[ihl:]
            if proto == 6 and len(l4) >= 20:      # TCP
                sport, dport = struct.unpack_from(">HH", l4, 0)
                doff = (l4[12] >> 4) * 4
                return Packet(ts, src, dst, sport, dport, "tcp", l4[doff:])
            if proto == 17 and len(l4) >= 8:      # UDP
                sport, dport = struct.unpack_from(">HH", l4, 0)
                return Packet(ts, src, dst, sport, dport, "udp", l4[8:])
            if proto == 1:                        # ICMP
                return Packet(ts, src, dst, 0, 0, "icmp", l4[4:])
            return None
        except Exception:
            return None

    # -------------------------------------------------- analises
    def _overview(self, ev, pkts):
        protos = Counter(p.proto for p in pkts)
        hosts = {p.src for p in pkts} | {p.dst for p in pkts}
        ports = Counter(p.dport for p in pkts if p.proto in ("tcp", "udp"))
        top_ports = ", ".join(f"{prt}({c})" for prt, c in ports.most_common(8))
        return Finding(
            analyzer=self.name, category="pcap",
            title=f"Captura com {len(pkts)} pacotes, {len(hosts)} hosts",
            severity=Severity.INFO, source=str(ev.path),
            description=(f"Protocolos: {dict(protos)}. Portas de destino frequentes: "
                        f"{top_ports}."),
            iocs={"ipv4": sorted(hosts)[:100]},
            data={"packets": len(pkts), "protocols": dict(protos)},
        )

    def _dns(self, ev, pkts):
        queries = []
        for p in pkts:
            if p.dport == 53 or p.sport == 53:
                name = self._dns_qname(p.payload)
                if name:
                    queries.append(name)
        if not queries:
            return []
        uniq = list(dict.fromkeys(queries))
        # dominios longos/entropicos = possivel tunel/exfil DNS
        suspicious = [q for q in uniq if len(q) > 50 or q.count(".") > 6]
        out = [Finding(
            analyzer=self.name, category="pcap",
            title=f"{len(uniq)} dominio(s) consultado(s) via DNS",
            severity=Severity.LOW, source=str(ev.path),
            evidence=", ".join(uniq[:15]),
            iocs={"domain": uniq[:100]},
        )]
        if suspicious:
            out.append(Finding(
                analyzer=self.name, category="pcap",
                title="Possivel tunelamento/exfiltracao via DNS",
                severity=Severity.HIGH, source=str(ev.path),
                description="Nomes DNS muito longos ou com muitos rotulos.",
                evidence=", ".join(suspicious[:10]),
                iocs={"domain": suspicious}, tags=["dns-tunnel", "exfil"],
                mitre=["T1048.003", "T1071.004"],
                recommendation="Investigar destino e volume; bloquear se malicioso.",
            ))
        return out

    @staticmethod
    def _dns_qname(payload: bytes) -> str | None:
        try:
            if len(payload) < 13:
                return None
            i = 12
            labels = []
            while i < len(payload):
                ln = payload[i]
                if ln == 0:
                    break
                if ln & 0xC0:  # ponteiro de compressao
                    break
                labels.append(payload[i + 1: i + 1 + ln].decode("ascii", "replace"))
                i += 1 + ln
            return ".".join(labels) if labels else None
        except Exception:
            return None

    def _http(self, ev, pkts):
        reqs = []
        for p in pkts:
            if p.proto != "tcp" or not p.payload:
                continue
            if p.payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE"):
                txt = p.payload.decode("latin-1", "replace")
                host = self._header(txt, "Host")
                ua = self._header(txt, "User-Agent")
                line = txt.split("\r\n", 1)[0]
                url = f"http://{host}{line.split(' ')[1]}" if host and ' ' in line else line
                reqs.append((url, ua))
        if not reqs:
            return []
        urls = list(dict.fromkeys(u for u, _ in reqs))
        uas = list(dict.fromkeys(ua for _, ua in reqs if ua))
        out = [Finding(
            analyzer=self.name, category="pcap",
            title=f"{len(reqs)} requisicao(oes) HTTP em texto claro",
            severity=Severity.MEDIUM, source=str(ev.path),
            description="Trafego HTTP nao cifrado capturado.",
            evidence="\n".join(urls[:12]),
            iocs={"url": urls[:100]}, tags=["cleartext-http"],
            recommendation="Migrar para HTTPS; inspecionar URLs por conteudo sensivel.",
        )]
        weird_ua = [u for u in uas if any(t in u.lower() for t in
                    ("curl", "python", "powershell", "wget", "go-http", "sqlmap", "nikto"))]
        if weird_ua:
            out.append(Finding(
                analyzer=self.name, category="pcap",
                title="User-Agent de ferramenta/automacao",
                severity=Severity.MEDIUM, source=str(ev.path),
                evidence="; ".join(weird_ua[:8]),
                tags=["tooling"], mitre=["T1071.001"],
            ))
        return out

    @staticmethod
    def _header(txt: str, name: str) -> str:
        for line in txt.split("\r\n"):
            if line.lower().startswith(name.lower() + ":"):
                return line.split(":", 1)[1].strip()
        return ""

    def _cleartext_creds(self, ev, pkts):
        creds = []
        for p in pkts:
            if not p.payload:
                continue
            txt = p.payload.decode("latin-1", "replace")
            # HTTP Basic
            if "Authorization: Basic" in txt:
                token = txt.split("Authorization: Basic", 1)[1].split("\r\n")[0].strip()
                try:
                    dec = base64.b64decode(token).decode("latin-1", "replace")
                    creds.append(("HTTP Basic", dec))
                except Exception:
                    pass
            # FTP / POP / IMAP / SMTP AUTH
            for kw in ("USER ", "PASS ", "LOGIN ", "AUTH "):
                if txt.startswith(kw) and p.dport in (21, 110, 143, 25, 587):
                    creds.append((f"porta {p.dport}", txt.strip()[:80]))
        if not creds:
            return []
        return [Finding(
            analyzer=self.name, category="pcap",
            title=f"{len(creds)} credencial(is) em texto claro na rede",
            severity=Severity.CRITICAL, source=str(ev.path),
            description="Credenciais trafegando sem cifra (sniffing trivial).",
            evidence="\n".join(f"{k}: {v}" for k, v in creds[:8]),
            tags=["credentials", "cleartext"], mitre=["T1040"],
            recommendation="Rotacionar credenciais e exigir canais cifrados.",
        )]

    def _flags_in_payload(self, ev, pkts):
        blob = b"".join(p.payload for p in pkts if p.payload)[: 8 * 1024 * 1024]
        fl = P.find_flags(blob.decode("latin-1", "replace"))
        if not fl:
            return []
        return [Finding(
            analyzer=self.name, category="pcap",
            title="Bandeira em payload de rede",
            severity=Severity.HIGH, source=str(ev.path),
            evidence="; ".join(fl[:5]), flags=fl,
        )]

    def _beaconing(self, ev, pkts):
        # Agrupa por (dst, dport) e mede regularidade dos intervalos.
        flows = defaultdict(list)
        for p in pkts:
            if p.proto == "tcp" and p.ts:
                flows[(p.dst, p.dport)].append(p.ts)
        out = []
        for (dst, dport), times in flows.items():
            if len(times) < 6:
                continue
            times.sort()
            gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
            if len(gaps) < 5:
                continue
            mean = sum(gaps) / len(gaps)
            if mean <= 0:
                continue
            var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
            cv = (var ** 0.5) / mean       # coeficiente de variacao
            if cv < 0.15 and mean > 1:     # muito regular = beacon
                out.append(Finding(
                    analyzer=self.name, category="pcap",
                    title=f"Padrao de beaconing para {dst}:{dport}",
                    severity=Severity.HIGH, source=str(ev.path),
                    description=(f"{len(times)} conexoes com intervalo medio "
                                f"{mean:.1f}s muito regular (CV={cv:.2f})."),
                    iocs={"ipv4": [dst]}, tags=["c2", "beacon"],
                    mitre=["T1071"], data={"interval_s": round(mean, 2)},
                    recommendation="Investigar como possivel canal de C2.",
                ))
        return out
