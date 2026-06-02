import os
import base64
import tempfile
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


FONT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fonts")
_style_sheet = None


def _get_styles():
    global _style_sheet
    if _style_sheet is not None:
        return _style_sheet

    styles = getSampleStyleSheet()

    cn_font_paths = [
        os.path.join(FONT_DIR, "NotoSansSC-Regular.ttf"),
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/simsun.ttc",
    ]
    cn_font_loaded = False
    for path in cn_font_paths:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("CJK", path))
                cn_font_loaded = True
                break
            except Exception:
                continue

    font_name = "CJK" if cn_font_loaded else "Helvetica"

    styles.add(ParagraphStyle(
        "CNTitle", fontName=font_name, fontSize=18, leading=24,
        alignment=1, spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        "CNBody", fontName=font_name, fontSize=10, leading=16,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "CNCode", fontName="Courier" if not cn_font_loaded else font_name,
        fontSize=8, leading=12, backColor=HexColor("#f5f5f5"),
        spaceAfter=4, wordWrap="CJK",
    ))
    _style_sheet = (styles, font_name)
    return _style_sheet


def fetch_chain_data(tx_hash_hex: str, encryption_mode: str) -> dict:
    try:
        from web3 import Web3
        from server.utils.config import NODE_URL

        w3 = Web3(Web3.HTTPProvider(NODE_URL))
        tx_hash_bytes = bytes.fromhex(tx_hash_hex.replace("0x", ""))
        tx = w3.eth.get_transaction(tx_hash_bytes)
        input_data = tx["input"]

        if encryption_mode == "sha3-256+ed25519":
            params = input_data[4:]
            return {
                "hash": "0x" + params[0:32].hex(),
                "signature": "0x" + params[32:96].hex(),
                "user_id": "0x" + params[96:128].hex(),
            }
        else:
            data = input_data[4:]
            hash_offset = int.from_bytes(data[0:32], "big")  # bytes offset
            sig_offset = int.from_bytes(data[32:64], "big")  # bytes offset
            user_id = "0x" + data[64:96].hex()               # bytes32 direct

            def _read_bytes(offset):
                length = int.from_bytes(data[offset:offset + 32], "big")
                return "0x" + data[offset + 32:offset + 32 + length].hex(), length

            hash_val, hash_len = _read_bytes(hash_offset)
            sig_val, sig_len = _read_bytes(sig_offset)

            return {
                "hash": hash_val,
                "hash_len": hash_len,
                "signature": sig_val,
                "sig_len": sig_len,
                "user_id": user_id,
            }
    except Exception:
        return {
            "hash": "链上数据暂不可用",
            "signature": "链上数据暂不可用",
            "user_id": "链上数据暂不可用",
        }


def generate_report(order: dict) -> bytes:
    styles, font_name = _get_styles()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_date = datetime.now().strftime("%Y-%m-%d")
    tx_hash_hex = order["tx_hash"].hex() if isinstance(order["tx_hash"], bytes) else order["tx_hash"]
    tx_short = tx_hash_hex[:16].replace("0x", "") if tx_hash_hex else "unknown"

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)

    chain_data = fetch_chain_data(tx_hash_hex, order["encryption_mode"])

    elements = []

    elements.append(Paragraph("Proof Of Creation 存证报告", styles["CNTitle"]))
    elements.append(Spacer(1, 4 * mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor("#1a73e8")))
    elements.append(Spacer(1, 6 * mm))

    onchain_ts = datetime.fromtimestamp(order["onchain_at"]).strftime("%Y-%m-%d %H:%M:%S") if order["onchain_at"] else "-"

    info_data = [
        ["订单备注名", order["file_name"]],
        ["报告生成时间", now_str],
        ["存证时间", onchain_ts],
        ["区块高度", str(order["block_number"]) if order["block_number"] else "-"],
        ["交易哈希", tx_hash_hex],
        ["加密模式", order["encryption_mode"]],
    ]

    for label, value in info_data:
        elements.append(Paragraph("<b>%s</b>: %s" % (label, value), styles["CNBody"]))
        elements.append(Spacer(1, 2 * mm))

    elements.append(Spacer(1, 8 * mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor("#1a73e8")))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph("<b>链上存证数据</b>", styles["CNTitle"]))
    elements.append(Spacer(1, 2 * mm))
    elements.append(Paragraph(
        "以下数据已写入以太坊区块链，不可篡改，永久可查。通过区块浏览器查询交易哈希即可独立验证。",
        ParagraphStyle("Hint", fontName=font_name, fontSize=8, textColor=HexColor("#666666"), spaceAfter=8),
    ))
    elements.append(Spacer(1, 4 * mm))

    if order["encryption_mode"] == "sha3-256+ed25519":
        hash_expected = 32
        sig_expected = 64
    else:
        hash_expected = chain_data.get("hash_len")
        sig_expected = chain_data.get("sig_len")

    onchain_items = [
        ("文件哈希", chain_data.get("hash", "-"), hash_expected),
        ("数字签名", chain_data.get("signature", "-"), sig_expected),
        ("签名者公钥指纹", chain_data.get("user_id", "-"), 32),
    ]

    for label, value, expected_len in onchain_items:
        elements.append(Paragraph("<b>%s</b>" % label, styles["CNBody"]))
        hex_str = (value or "").replace("0x", "")
        try:
            raw = bytes.fromhex(hex_str) if hex_str and hex_str != "-" and "暂不可用" not in hex_str else b""
            b64 = base64.b64encode(raw).decode() if raw else "-"
        except Exception:
            b64 = "-"
        elements.append(Paragraph("HEX:    %s" % (value if value else "-"), styles["CNCode"]))
        elements.append(Paragraph("Base64: %s" % b64, styles["CNCode"]))
        if expected_len:
            elements.append(Paragraph("长度: %d 字节" % expected_len, ParagraphStyle(
                "Hint2", fontName=font_name, fontSize=7, textColor=HexColor("#999999"), spaceAfter=4)))
        elements.append(Spacer(1, 2 * mm))

    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#cccccc")))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(
        "本报告由 Proof Of Creation 平台自动生成。存证数据已写入区块链，任何人可通过交易哈希在区块浏览器中独立验证。",
        ParagraphStyle("Footer", fontName=font_name, fontSize=8, textColor=HexColor("#999999"), alignment=1),
    ))

    doc.build(elements)
    pdf_data = buf.getvalue()
    buf.close()
    return pdf_data, file_date, tx_short
