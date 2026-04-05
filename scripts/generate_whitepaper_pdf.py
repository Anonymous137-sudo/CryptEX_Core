#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import html
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "archives" / "CryptEX_Whitepaper_Source_April_2026.md"
OUTPUT = ROOT / "WHITEPAPER.pdf"
LOGO = ROOT / "gui" / "resources" / "CryptEX.png"

FONT_DIR = Path("/System/Library/Fonts/Supplemental")
REGULAR = FONT_DIR / "Times New Roman.ttf"
BOLD = FONT_DIR / "Times New Roman Bold.ttf"
ITALIC = FONT_DIR / "Times New Roman Italic.ttf"
BOLDITALIC = FONT_DIR / "Times New Roman Bold Italic.ttf"


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont("CrxTimes", str(REGULAR)))
    pdfmetrics.registerFont(TTFont("CrxTimesBold", str(BOLD)))
    pdfmetrics.registerFont(TTFont("CrxTimesItalic", str(ITALIC)))
    pdfmetrics.registerFont(TTFont("CrxTimesBoldItalic", str(BOLDITALIC)))


def styles():
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        "CrxTitle",
        parent=base["Title"],
        fontName="CrxTimesBold",
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10,
        textColor=colors.HexColor("#111111"),
    )
    subtitle = ParagraphStyle(
        "CrxSubtitle",
        parent=base["Normal"],
        fontName="CrxTimesItalic",
        fontSize=13,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2d2d2d"),
        spaceAfter=8,
    )
    meta = ParagraphStyle(
        "CrxMeta",
        parent=base["Normal"],
        fontName="CrxTimes",
        fontSize=10.5,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        spaceAfter=18,
    )
    h1 = ParagraphStyle(
        "CrxH1",
        parent=base["Heading1"],
        fontName="CrxTimesBold",
        fontSize=17,
        leading=22,
        textColor=colors.HexColor("#111111"),
        spaceBefore=18,
        spaceAfter=10,
    )
    h2 = ParagraphStyle(
        "CrxH2",
        parent=base["Heading2"],
        fontName="CrxTimesBold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1d1d1d"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body = ParagraphStyle(
        "CrxBody",
        parent=base["BodyText"],
        fontName="CrxTimes",
        fontSize=11.5,
        leading=17,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor("#171717"),
        spaceAfter=8,
    )
    bullet = ParagraphStyle(
        "CrxBullet",
        parent=body,
        leftIndent=18,
        firstLineIndent=-10,
        bulletIndent=8,
        spaceAfter=4,
    )
    formula = ParagraphStyle(
        "CrxFormula",
        parent=base["Code"],
        fontName="CrxTimesItalic",
        fontSize=12,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#111111"),
        spaceBefore=4,
        spaceAfter=10,
    )
    caption = ParagraphStyle(
        "CrxCaption",
        parent=base["Normal"],
        fontName="CrxTimesItalic",
        fontSize=10,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#444444"),
        spaceBefore=4,
        spaceAfter=10,
    )
    return {
        "title": title,
        "subtitle": subtitle,
        "meta": meta,
        "h1": h1,
        "h2": h2,
        "body": body,
        "bullet": bullet,
        "formula": formula,
        "caption": caption,
    }


def inline_markup(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"\*(.+?)\*", r"<i>\1</i>", escaped)
    escaped = escaped.replace("—", "&#8212;")
    return escaped


def iter_blocks(lines: list[str]):
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        if not line.strip():
            i += 1
            continue
        diagram_match = re.fullmatch(r"\[\[DIAGRAM:\s*([a-zA-Z0-9_]+)\s*\]\]", line.strip())
        if diagram_match:
            yield ("diagram", diagram_match.group(1))
            i += 1
            continue
        if line.strip() == "$$":
            i += 1
            formula_lines = []
            while i < len(lines) and lines[i].strip() != "$$":
                formula_lines.append(lines[i].rstrip("\n"))
                i += 1
            i += 1
            yield ("formula", " ".join(l.strip() for l in formula_lines if l.strip()))
            continue
        if line.startswith("# "):
            yield ("title", line[2:].strip())
            i += 1
            continue
        if line.startswith("## "):
            yield ("h1", line[3:].strip())
            i += 1
            continue
        if line.startswith("### "):
            yield ("h2", line[4:].strip())
            i += 1
            continue
        if line.startswith("- "):
            yield ("bullet", line[2:].strip())
            i += 1
            continue
        paragraph = [line.strip()]
        i += 1
        while i < len(lines):
            nxt = lines[i].rstrip("\n")
            if not nxt.strip() or nxt.startswith("#") or nxt.startswith("- ") or nxt.strip() == "$$":
                break
            paragraph.append(nxt.strip())
            i += 1
        yield ("paragraph", " ".join(paragraph))


def _box(d: Drawing, x: float, y: float, w: float, h: float, text: str,
         fill: str = "#f5f7fb", stroke: str = "#334155", text_color: str = "#111111") -> None:
    d.add(
        Rect(
            x,
            y,
            w,
            h,
            rx=8,
            ry=8,
            fillColor=colors.HexColor(fill),
            strokeColor=colors.HexColor(stroke),
            strokeWidth=1.1,
        )
    )
    lines = text.split("\n")
    start_y = y + h / 2 + (len(lines) - 1) * 6
    for idx, line in enumerate(lines):
        d.add(
            String(
                x + w / 2,
                start_y - idx * 12,
                line,
                textAnchor="middle",
                fontName="CrxTimes",
                fontSize=10,
                fillColor=colors.HexColor(text_color),
            )
        )


def _arrow(d: Drawing, x1: float, y1: float, x2: float, y2: float, color: str = "#4b5563") -> None:
    d.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor(color), strokeWidth=1.3))
    angle = 0.0
    dx = x2 - x1
    dy = y2 - y1
    if dx == 0 and dy == 0:
        return
    import math

    angle = math.atan2(dy, dx)
    head_len = 8
    head_ang = math.pi / 7
    x3 = x2 - head_len * math.cos(angle - head_ang)
    y3 = y2 - head_len * math.sin(angle - head_ang)
    x4 = x2 - head_len * math.cos(angle + head_ang)
    y4 = y2 - head_len * math.sin(angle + head_ang)
    d.add(
        Polygon(
            points=[x2, y2, x3, y3, x4, y4],
            fillColor=colors.HexColor(color),
            strokeColor=colors.HexColor(color),
        )
    )


def build_diagram(name: str) -> tuple[Drawing, str] | None:
    if name == "system_architecture":
        d = Drawing(430, 240)
        _box(d, 155, 192, 120, 30, "Qt Desktop Client", fill="#eef4ff", stroke="#1d4ed8")
        _box(d, 150, 128, 130, 38, "JSON-RPC / CLI\nControl Plane", fill="#f5f3ff", stroke="#6d28d9")
        _box(d, 70, 56, 92, 40, "Consensus\nChain Engine", fill="#f8fafc")
        _box(d, 170, 56, 92, 40, "Wallet\nSubsystem", fill="#f8fafc")
        _box(d, 270, 56, 92, 40, "Mining\nEngine", fill="#f8fafc")
        _box(d, 20, 8, 120, 28, "P2P Network", fill="#ecfeff", stroke="#0f766e")
        _box(d, 155, 8, 120, 28, "Chainstate / Blocks", fill="#fff7ed", stroke="#c2410c")
        _box(d, 290, 8, 120, 28, "Wallet.dat / Peer State", fill="#fff7ed", stroke="#c2410c")
        _arrow(d, 215, 192, 215, 166)
        _arrow(d, 215, 128, 116, 96)
        _arrow(d, 215, 128, 216, 96)
        _arrow(d, 215, 128, 316, 96)
        _arrow(d, 116, 56, 80, 36)
        _arrow(d, 216, 56, 215, 36)
        _arrow(d, 316, 56, 350, 36)
        caption = "Figure 1. System architecture. The Qt client is separated from the daemon and reaches consensus, wallet, and mining state through the RPC control plane."
        return d, caption

    if name == "difficulty_controller":
        d = Drawing(430, 220)
        _box(d, 18, 144, 88, 34, "LWMA\nEstimate", fill="#eff6ff", stroke="#2563eb")
        _box(d, 18, 92, 88, 34, "EMA\nSmoother", fill="#eff6ff", stroke="#2563eb")
        _box(d, 18, 40, 88, 34, "Overdue Gap\nΔ / τ", fill="#eff6ff", stroke="#2563eb")
        _box(d, 156, 88, 120, 46, "Adaptive Target\nController", fill="#eef2ff", stroke="#4338ca")
        _box(d, 322, 94, 90, 34, "T₍next₎", fill="#ecfeff", stroke="#0f766e")
        _box(d, 304, 22, 108, 34, "Emergency Rule\nΔ ≥ 2τ", fill="#fff7ed", stroke="#c2410c")
        _arrow(d, 106, 161, 156, 122)
        _arrow(d, 106, 109, 156, 111)
        _arrow(d, 106, 57, 156, 100)
        _arrow(d, 276, 111, 322, 111)
        _arrow(d, 358, 56, 358, 94)
        d.add(String(215, 188, "Hash-rate cliff -> liveness recovery", textAnchor="middle", fontName="CrxTimesItalic", fontSize=10, fillColor=colors.HexColor("#374151")))
        caption = "Figure 2. Adaptive liveness controller. Historical weighting, short-horizon smoothing, real-time lateness, and the emergency rule jointly determine the next target."
        return d, caption

    if name == "sync_pipeline":
        d = Drawing(430, 170)
        _box(d, 10, 70, 72, 34, "Peer\nDiscovery", fill="#ecfeff", stroke="#0f766e")
        _box(d, 98, 70, 72, 34, "Headers", fill="#eff6ff", stroke="#2563eb")
        _box(d, 186, 70, 72, 34, "Block\nFetch", fill="#eff6ff", stroke="#2563eb")
        _box(d, 274, 70, 72, 34, "Full\nValidation", fill="#f5f3ff", stroke="#6d28d9")
        _box(d, 362, 70, 58, 34, "Activate", fill="#eef2ff", stroke="#4338ca")
        _box(d, 274, 16, 146, 28, "Wallet / RPC / GUI state", fill="#fff7ed", stroke="#c2410c")
        _arrow(d, 82, 87, 98, 87)
        _arrow(d, 170, 87, 186, 87)
        _arrow(d, 258, 87, 274, 87)
        _arrow(d, 346, 87, 362, 87)
        _arrow(d, 391, 70, 347, 44)
        d.add(String(46, 118, "LAN / DNS / saved peers", textAnchor="middle", fontName="CrxTimesItalic", fontSize=9, fillColor=colors.HexColor("#4b5563")))
        caption = "Figure 3. Synchronization pipeline. Discovery, header acquisition, block download, validation, and activation are separated before state is exposed to wallet and GUI surfaces."
        return d, caption

    return None


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("CrxTimes", 9)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawCentredString(A4[0] / 2.0, 0.48 * inch, str(doc.page))
    canvas.restoreState()


def build_pdf(source: Path, output: Path) -> None:
    register_fonts()
    s = styles()
    lines = source.read_text(encoding="utf-8").splitlines()
    story = []

    title_consumed = False
    subtitle_consumed = False
    meta_consumed = 0

    if LOGO.exists():
        img = Image(str(LOGO), width=1.35 * inch, height=1.35 * inch)
        img.hAlign = "CENTER"
        story.append(Spacer(1, 0.35 * inch))
        story.append(img)
        story.append(Spacer(1, 0.18 * inch))

    for kind, value in iter_blocks(lines):
        if kind == "title" and not title_consumed:
            story.append(Paragraph(inline_markup(value), s["title"]))
            title_consumed = True
            continue
        if kind == "paragraph" and title_consumed and not subtitle_consumed:
            story.append(Paragraph(inline_markup(value), s["subtitle"]))
            subtitle_consumed = True
            continue
        if kind == "paragraph" and title_consumed and subtitle_consumed and meta_consumed < 1 and value.startswith("Implementation reference"):
            story.append(Paragraph(inline_markup(value), s["meta"]))
            meta_consumed += 1
            continue
        if kind == "paragraph" and title_consumed and subtitle_consumed and meta_consumed < 2 and value.startswith("Version:"):
            story.append(Paragraph(inline_markup(value), s["meta"]))
            story.append(Spacer(1, 0.08 * inch))
            meta_consumed += 1
            continue

        if kind == "h1":
            story.append(Paragraph(inline_markup(value), s["h1"]))
        elif kind == "h2":
            story.append(Paragraph(inline_markup(value), s["h2"]))
        elif kind == "bullet":
            story.append(Paragraph(f"• {inline_markup(value)}", s["bullet"]))
        elif kind == "formula":
            story.append(Spacer(1, 0.03 * inch))
            story.append(Paragraph(inline_markup(value), s["formula"]))
        elif kind == "diagram":
            built = build_diagram(value)
            if built is not None:
                drawing, caption = built
                story.append(Spacer(1, 0.05 * inch))
                story.append(drawing)
                story.append(Paragraph(inline_markup(caption), s["caption"]))
        elif kind == "paragraph":
            story.append(Paragraph(inline_markup(value), s["body"]))

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=0.95 * inch,
        rightMargin=0.95 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.75 * inch,
        title="CryptEX Whitepaper",
        author="CryptEX",
        subject="Technical whitepaper",
    )
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


if __name__ == "__main__":
    src = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else SOURCE
    out = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else OUTPUT
    build_pdf(src, out)
    print(out)
