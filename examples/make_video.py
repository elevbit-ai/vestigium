"""Gera um video MP4 explicando como o Vestigium funciona.

Renderiza quadros com Pillow e codifica em H.264 via ffmpeg (pipe rawvideo).
Nao usa audio. Saida padrao: docs/assets/vestigium-demo.mp4

Uso:  python examples/make_video.py [saida.mp4]

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import math
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- config
W, H, FPS = 1920, 1080, 30
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else \
    Path(__file__).resolve().parents[1] / "docs" / "assets" / "vestigium-demo.mp4"

# cores (RGB)
TXT = (234, 238, 251)
MUTED = (147, 160, 196)
ACCENT = (110, 168, 254)
ACCENT2 = (139, 125, 255)
GREEN = (74, 222, 128)
RED = (239, 68, 68)
ORANGE = (249, 115, 22)
AMBER = (234, 179, 8)
BLUE = (59, 130, 246)
PANEL = (19, 27, 56)
LINE = (38, 48, 90)

FONTS = "C:/Windows/Fonts/"


def _font(name, size):
    try:
        return ImageFont.truetype(FONTS + name, size)
    except OSError:
        return ImageFont.load_default()


def reg(s): return _font("segoeui.ttf", s)
def bold(s): return _font("segoeuib.ttf", s)
def semi(s): return _font("seguisb.ttf", s)
def mono(s): return _font("consola.ttf", s)
def monob(s): return _font("consolab.ttf", s)


# ---------------------------------------------------------------- helpers
def clamp(v, lo=0.0, hi=1.0): return max(lo, min(hi, v))
def lerp(a, b, t): return a + (b - a) * t
def ease(t): t = clamp(t); return t * t * (3 - 2 * t)


def appear(t, start, fade=0.45):
    return ease((t - start) / fade) if fade else float(t >= start)


def disappear(t, start, fade=0.4):
    return 1.0 - ease((t - start) / fade) if fade else float(t < start)


def col(rgb, a):
    return (rgb[0], rgb[1], rgb[2], int(255 * clamp(a)))


def build_bg():
    y, x = np.mgrid[0:H, 0:W].astype(np.float32)
    top = np.array([9, 14, 30], np.float32)
    bot = np.array([13, 19, 44], np.float32)
    img = top + (bot - top) * (y / H)[..., None]

    def glow(cx, cy, rad, color, strength):
        d = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)
        g = np.clip(1 - d / rad, 0, 1) ** 2
        return g[..., None] * np.array(color, np.float32) * strength

    img += glow(0.74 * W, -0.12 * H, 1000, ACCENT, 0.16)
    img += glow(0.12 * W, 0.12 * H, 900, ACCENT2, 0.13)
    img += glow(0.85 * W, 1.05 * H, 850, ACCENT, 0.08)
    return Image.fromarray(np.clip(img, 0, 255).astype("uint8"), "RGB").convert("RGBA")


BG = build_bg()


def text(d, xy, s, font, fill, a=1.0, anchor="lm"):
    d.text(xy, s, font=font, fill=col(fill, a), anchor=anchor)


def rounded(d, box, radius, fill=None, outline=None, width=1, a=1.0):
    f = col(fill, a) if fill else None
    o = col(outline, a) if outline else None
    d.rounded_rectangle(box, radius=radius, fill=f, outline=o, width=width)


def magnifier(d, cx, cy, r, thick, color, a=1.0):
    """Desenha uma lupa vetorial (icone da marca)."""
    c = col(color, a)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=c, width=thick)
    hx, hy = cx + r * 0.72, cy + r * 0.72
    ex, ey = hx + r * 0.75, hy + r * 0.75
    d.line([hx, hy, ex, ey], fill=c, width=thick + 2)


def watermark(d, a=1.0):
    magnifier(d, 70, 58, 15, 4, ACCENT, a * 0.9)
    text(d, (98, 58), "Vestigium", semi(28), TXT, a * 0.9, anchor="lm")


def progress(d, t, total):
    p = clamp(t / total)
    d.rectangle([0, H - 6, W, H], fill=col(PANEL, 1))
    grad_w = int(W * p)
    if grad_w > 0:
        d.rectangle([0, H - 6, grad_w, H], fill=col(ACCENT, 1))


# ---------------------------------------------------------------- scenes
def s_intro(d, t, dur):
    a = appear(t, 0.2, 0.8) * disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    # lupa central com leve escala
    scale = lerp(0.85, 1.0, ease((t - 0.2) / 1.0))
    magnifier(d, cx, 380, int(70 * scale), 9, ACCENT, a)
    text(d, (cx, 520), "VESTIGIUM", bold(120), TXT, a, anchor="mm")
    text(d, (cx, 610), "agente autonomo de analise forense e CTF",
         reg(40), MUTED, a * appear(t, 0.9, 0.8), anchor="mm")
    cats = "PCAP   LOG   SQLite   Stego   Crypto   Warmup   Phishing   Cadeia   Dropper"
    text(d, (cx, 700), cats, semi(28), ACCENT,
         a * appear(t, 1.4, 0.9), anchor="mm")


def s_what(d, t, dur):
    watermark(d, appear(t, 0.1))
    a_out = disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    text(d, (cx, 260), "Voce aponta para as evidencias.",
         bold(66), TXT, appear(t, 0.2, 0.7) * a_out, anchor="mm")
    text(d, (cx, 350), "O agente faz o resto.",
         bold(66), ACCENT, appear(t, 0.7, 0.7) * a_out, anchor="mm")

    # pasta de evidencias mistas
    items = ["captura.pcap", "acesso.log", "app.db", "imagem.png",
             "email.eml", "fatura.ps1", "desafio.txt", "dump.bin"]
    bw, bh, gap = 300, 78, 26
    cols = 4
    total_w = cols * bw + (cols - 1) * gap
    x0 = (W - total_w) / 2
    y0 = 480
    for i, name in enumerate(items):
        r, c = divmod(i, cols)
        bx = x0 + c * (bw + gap)
        by = y0 + r * (bh + gap)
        aa = appear(t, 1.2 + i * 0.12, 0.4) * a_out
        rounded(d, [bx, by, bx + bw, by + bh], 14, PANEL, LINE, 2, aa)
        d.rectangle([bx + 18, by + bh / 2 - 12, bx + 42, by + bh / 2 + 12],
                    fill=col(ACCENT, aa * 0.9))
        text(d, (bx + 62, by + bh / 2), name, mono(30), TXT, aa, anchor="lm")


PIPE = [
    ("1", "Percepcao", "Identifica cada arquivo por magic bytes, hash e entropia"),
    ("2", "Roteamento", "Escolhe quais analisadores se aplicam a cada evidencia"),
    ("3", "Analise", "Emite achados com severidade, IOCs e tecnica MITRE ATT&CK"),
    ("4", "Correlacao", "Cruza IOCs e reconstroi a cadeia de ataque (kill chain)"),
    ("5", "Sintese", "Calcula o risco 0-100 e gera o relatorio profissional"),
]


def s_pipeline(d, t, dur):
    watermark(d)
    a_out = disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    text(d, (cx, 150), "Um agente, cinco etapas", bold(60), TXT,
         appear(t, 0.1, 0.6) * a_out, anchor="mm")

    n = len(PIPE)
    bw, bh, gap = 300, 200, 42
    total_w = n * bw + (n - 1) * gap
    x0 = (W - total_w) / 2
    y0 = 360
    last = -1
    for i, (num, title, _desc) in enumerate(PIPE):
        start = 0.6 + i * 0.9
        aa = appear(t, start, 0.5) * a_out
        if t >= start:
            last = i
        bx = x0 + i * (bw + gap)
        # conector com pulso
        if i > 0:
            lx0 = bx - gap - 6
            ca = appear(t, start - 0.2, 0.4) * a_out
            d.line([lx0, y0 + bh / 2, bx + 6, y0 + bh / 2],
                   fill=col(LINE, ca), width=4)
            # ponta de seta
            d.polygon([(bx - 2, y0 + bh / 2 - 9), (bx + 12, y0 + bh / 2),
                       (bx - 2, y0 + bh / 2 + 9)], fill=col(ACCENT, ca))
        rounded(d, [bx, y0, bx + bw, y0 + bh], 20, PANEL, LINE, 2, aa)
        # badge numerado
        badge = 42
        d.ellipse([bx + 28, y0 + 28, bx + 28 + badge, y0 + 28 + badge],
                  fill=col(ACCENT, aa))
        text(d, (bx + 28 + badge / 2, y0 + 28 + badge / 2), num,
             bold(30), (9, 18, 46), aa, anchor="mm")
        text(d, (bx + bw / 2, y0 + 140), title, bold(34), TXT, aa, anchor="mm")

    # descricao dinamica da etapa mais recente
    if last >= 0:
        desc = PIPE[last][2]
        da = appear(t, 0.6 + last * 0.9 + 0.2, 0.4) * a_out
        text(d, (cx, y0 + bh + 90), desc, reg(38), MUTED, da, anchor="mm")


ANALYZERS = [
    ("Warmup", "triagem inicial e flags", AMBER),
    ("PCAP", "trafego, credenciais, C2", ACCENT),
    ("Log", "SQLi, XSS, brute force", BLUE),
    ("SQLite", "PII e registros apagados", GREEN),
    ("Stego", "dados ocultos em imagens", ACCENT2),
    ("Crypto", "decodifica e desofusca", (236, 72, 153)),
    ("Phishing", "spoofing e domínio sosia", ORANGE),
    ("Dropper", "malware e ofuscacao", RED),
    ("Cadeia", "correlaciona tudo", ACCENT),
]


def s_analyzers(d, t, dur):
    watermark(d)
    a_out = disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    text(d, (cx, 140), "Nove analisadores especializados", bold(58), TXT,
         appear(t, 0.1, 0.6) * a_out, anchor="mm")

    cols = 3
    cw, ch, gap = 480, 200, 40
    total_w = cols * cw + (cols - 1) * gap
    x0 = (W - total_w) / 2
    y0 = 280
    for i, (name, desc, c) in enumerate(ANALYZERS):
        r, cc = divmod(i, cols)
        bx = x0 + cc * (cw + gap)
        by = y0 + r * (ch + gap)
        start = 0.5 + i * 0.28
        pop = appear(t, start, 0.4)
        aa = pop * a_out
        rounded(d, [bx, by, bx + cw, by + ch], 18, PANEL, LINE, 2, aa)
        # barra de acento lateral
        d.rounded_rectangle([bx, by, bx + 8, by + ch], radius=4, fill=col(c, aa))
        d.ellipse([bx + 34, by + 34, bx + 74, by + 74], outline=col(c, aa), width=5)
        text(d, (bx + 100, by + 58), name, bold(38), TXT, aa, anchor="lm")
        text(d, (bx + 40, by + 130), desc, reg(30), MUTED, aa, anchor="lm")


TERM_LINES = [
    ("$ vestigium scan ./evidencias -o relatorio/", GREEN, 0.3),
    ("[16:02] Percepcao: 8 arquivo(s) identificado(s)", MUTED, 1.4),
    ("[16:02] Roteamento: captura.pcap -> warmup, pcap", MUTED, 2.2),
    ("  + pcap: credenciais em claro | beaconing C2", TXT, 3.0),
    ("[16:02] Roteamento: acesso.log -> log", MUTED, 3.7),
    ("  + log: SQLi, path traversal, forca bruta", TXT, 4.3),
    ("[16:03] Roteamento: app.db -> sqlite", MUTED, 5.0),
    ("  + sqlite: PII + registros apagados recuperados", TXT, 5.6),
    ("[16:03] Roteamento: imagem.png -> stego", MUTED, 6.3),
    ("  + stego: dados apos o EOF (polyglot)", TXT, 6.9),
    ("[16:03] Roteamento: fatura.ps1 -> dropper", MUTED, 7.6),
    ("  + dropper: cadeia completa (download+exec+evasao)", TXT, 8.2),
    ("[16:03] Correlacao: cadeia de ataque reconstruida", ACCENT, 9.0),
]


def s_terminal(d, t, dur):
    watermark(d)
    a_out = disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    # janela de terminal
    tx0, ty0, tx1, ty1 = 260, 150, W - 260, H - 180
    win_a = appear(t, 0.1, 0.5) * a_out
    rounded(d, [tx0, ty0, tx1, ty1], 18, (6, 10, 23), LINE, 2, win_a)
    d.line([tx0, ty0 + 56, tx1, ty0 + 56], fill=col(LINE, win_a), width=2)
    for i, dc in enumerate([RED, AMBER, GREEN]):
        d.ellipse([tx0 + 28 + i * 30, ty0 + 20, tx0 + 44 + i * 30, ty0 + 36],
                  fill=col(dc, win_a))
    text(d, (cx, ty0 + 28), "vestigium - scan", mono(26), MUTED, win_a, anchor="mm")

    f = mono(30)
    lh = 46
    ly = ty0 + 96
    for txt_line, c, start in TERM_LINES:
        if t < start:
            continue
        # efeito de maquina de escrever
        chars = int(clamp((t - start) / 0.5) * len(txt_line))
        shown = txt_line[:chars]
        text(d, (tx0 + 40, ly), shown, f, c, win_a, anchor="lm")
        ly += lh

    # resumo final destacado
    ra = appear(t, 10.2, 0.6) * a_out
    if ra > 0:
        by = ty1 - 120
        rounded(d, [tx0 + 30, by, tx1 - 30, ty1 - 30], 14, (30, 12, 18), RED, 2, ra)
        text(d, (tx0 + 60, by + 45), "RISCO: CRITICO  100/100",
             monob(38), RED, ra, anchor="lm")
        text(d, (tx1 - 60, by + 45),
             "6 flags  |  47 achados  |  3.1s", mono(30), MUTED, ra, anchor="rm")


def draw_gauge(d, cx, cy, r, frac, a):
    # arco de fundo
    d.arc([cx - r, cy - r, cx + r, cy + r], 135, 405, fill=col(LINE, a), width=26)
    # arco preenchido com cor por faixa
    end = 135 + 270 * frac
    color = GREEN if frac < 0.2 else AMBER if frac < 0.45 else ORANGE if frac < 0.75 else RED
    if frac > 0:
        d.arc([cx - r, cy - r, cx + r, cy + r], 135, end, fill=col(color, a), width=26)
    text(d, (cx, cy - 8), f"{int(frac * 100)}", bold(96), TXT, a, anchor="mm")
    text(d, (cx, cy + 60), "indice de risco", reg(30), MUTED, a, anchor="mm")


def s_report(d, t, dur):
    watermark(d)
    a_out = disappear(t, dur - 0.6, 0.6)
    cx = W / 2
    text(d, (cx, 120), "Um relatorio que voce pode entregar", bold(56), TXT,
         appear(t, 0.1, 0.6) * a_out, anchor="mm")

    # medidor de risco (esquerda)
    frac = ease(clamp((t - 0.6) / 2.0))
    ga = appear(t, 0.5, 0.5) * a_out
    draw_gauge(d, 560, 480, 200, frac, ga)

    # cartoes de severidade (direita)
    sev = [("Critica", 4, RED), ("Alta", 26, ORANGE), ("Media", 5, AMBER),
           ("Baixa", 2, GREEN), ("Info", 10, BLUE)]
    x0 = 940
    cw, chh, gap = 180, 150, 20
    for i, (lbl, val, c) in enumerate(sev):
        bx = x0 + i * (cw + gap)
        by = 370
        aa = appear(t, 0.8 + i * 0.18, 0.4) * a_out
        rounded(d, [bx, by, bx + cw, by + chh], 14, PANEL, c, 3, aa)
        count = int(val * ease(clamp((t - (0.8 + i * 0.18)) / 0.9)))
        text(d, (bx + cw / 2, by + 60), str(count), bold(56), c, aa, anchor="mm")
        text(d, (bx + cw / 2, by + 115), lbl, reg(26), MUTED, aa, anchor="mm")

    # flags recuperadas
    fa = appear(t, 2.2, 0.6) * a_out
    fy0 = 600
    box_l, box_r = 940, 940 + 5 * (cw + gap) - gap  # alinhado aos cartoes
    rounded(d, [box_l, fy0, box_r, fy0 + 300], 16,
            (15, 37, 25), (31, 122, 77), 2, fa)
    text(d, (box_l + 30, fy0 + 45), "Bandeiras recuperadas automaticamente",
         semi(30), GREEN, fa, anchor="lm")
    flags = ["flag{trafego_em_claro}", "flag{apos_o_eof}", "flag{base64_aninhado}",
             "flag{registro_no_banco}", "flag{rot_treze}", "flag{warmup_direto}"]
    fx, fy = box_l + 30, fy0 + 100
    for i, fl in enumerate(flags):
        fla = appear(t, 2.6 + i * 0.2, 0.35) * a_out
        w = 8 + len(fl) * 15
        if fx + w > box_r - 30:
            fx = box_l + 30
            fy += 56
        rounded(d, [fx, fy, fx + w, fy + 42], 8, (10, 28, 19), None, 0, fla)
        text(d, (fx + 14, fy + 21), fl, mono(24), (134, 239, 172), fla, anchor="lm")
        fx += w + 16


def s_outro(d, t, dur):
    a = appear(t, 0.2, 0.7)
    cx = W / 2
    magnifier(d, cx, 340, 60, 8, ACCENT, a)
    text(d, (cx, 470), "VESTIGIUM", bold(96), TXT, a, anchor="mm")
    text(d, (cx, 560), "Codigo aberto - MIT - zero dependencias",
         reg(36), MUTED, a * appear(t, 0.6, 0.6), anchor="mm")
    text(d, (cx, 660), "github.com/elevbit-ai/vestigium",
         semi(38), ACCENT, a * appear(t, 1.0, 0.6), anchor="mm")
    text(d, (cx, 720), "elevbit-ai.github.io/vestigium",
         semi(34), ACCENT2, a * appear(t, 1.2, 0.6), anchor="mm")
    text(d, (cx, 820), "Joaquim Pedro de Morais Filho  -  j360074@hotmail.com",
         reg(30), MUTED, a * appear(t, 1.5, 0.6), anchor="mm")


# ---------------------------------------------------------------- timeline
TIMELINE = [
    (s_intro, 5.0),
    (s_what, 5.5),
    (s_pipeline, 13.5),
    (s_analyzers, 10.5),
    (s_terminal, 14.0),
    (s_report, 10.0),
    (s_outro, 5.5),
]
TOTAL = sum(d for _, d in TIMELINE)


def render():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ffmpeg", "-y", "-f", "rawvideo", "-pixel_format", "rgb24",
        "-video_size", f"{W}x{H}", "-framerate", str(FPS), "-i", "-",
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "21",
        "-preset", "medium", "-movflags", "+faststart", str(OUT),
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    total_frames = int(TOTAL * FPS)
    elapsed = 0.0
    frame_idx = 0
    for scene, dur in TIMELINE:
        nf = int(dur * FPS)
        for k in range(nf):
            t = k / FPS
            img = BG.copy()
            d = ImageDraw.Draw(img, "RGBA")
            scene(d, t, dur)
            progress(d, elapsed + t, TOTAL)
            proc.stdin.write(img.convert("RGB").tobytes())
            frame_idx += 1
            if frame_idx % 60 == 0:
                pct = 100 * frame_idx / total_frames
                print(f"\r  renderizando... {pct:5.1f}%  "
                      f"({frame_idx}/{total_frames} quadros)", end="", flush=True)
        elapsed += dur
    proc.stdin.close()
    proc.wait()
    print(f"\nVideo gerado: {OUT}  ({OUT.stat().st_size/1e6:.1f} MB, "
          f"{TOTAL:.0f}s @ {FPS}fps)")


if __name__ == "__main__":
    render()
