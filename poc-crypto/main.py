import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

HASH_ALGOS = [
    "SHA-256", "SHA-512", "SHA3-256", "SHA3-512",
    "BLAKE2b-256", "BLAKE2s-256",
]

from pqcrypto._sign import ml_dsa_44, ml_dsa_65, ml_dsa_87
from pqcrypto._sign import sphincs_sha2_128s_simple

PQ_ALGOS = {
    "Dilithium2": ml_dsa_44,
    "Dilithium3": ml_dsa_65,
    "Dilithium5": ml_dsa_87,
    "SPHINCS+-128s": sphincs_sha2_128s_simple,
}

SIGN_ALGOS = [
    "Ed25519",
    "SHA256withRSA-2048",
    "SHA512withRSA-2048",
] + list(PQ_ALGOS.keys())

KEY_ALGOS = [
    "Ed25519",
    "RSA-2048",
] + list(PQ_ALGOS.keys())

OID_TO_ALGO = {
    b'\x2b\x65\x70': "Ed25519",
    b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': "RSA-2048",
    b'\x60\x86\x48\x01\x65\x03\x04\x03\x11': "Dilithium2",
    b'\x60\x86\x48\x01\x65\x03\x04\x03\x12': "Dilithium3",
    b'\x60\x86\x48\x01\x65\x03\x04\x03\x13': "Dilithium5",
    b'\x60\x86\x48\x01\x65\x03\x04\x03\x14': "SPHINCS+-128s",
}
ALGO_TO_OID = {v: k for k, v in OID_TO_ALGO.items()}

DRAFT_OID_ALGOS = {"Dilithium2", "Dilithium3", "Dilithium5", "SPHINCS+-128s"}
NO_DERIVE_ALGOS = {"RSA-2048", "SPHINCS+-128s"}

# ── ASN.1 DER helpers ──────────────────────────────────

def _encode_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    result = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = []
        while p > 0:
            enc.insert(0, p & 0x7F)
            p >>= 7
        if not enc:
            enc = [0]
        for i in range(len(enc) - 1):
            enc[i] |= 0x80
        result += bytes(enc)
    return result

def _encode_der_length(n):
    if n < 128:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded

def _decode_der_length(data, offset):
    if data[offset] < 128:
        return data[offset], offset + 1
    num_bytes = data[offset] & 0x7F
    length = int.from_bytes(data[offset + 1:offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes

def _wrap_pkcs8(oid_der, raw_key):
    oid_full = b'\x06' + _encode_der_length(len(oid_der)) + oid_der
    algo_id = b'\x30' + _encode_der_length(len(oid_full)) + oid_full
    priv_key = b'\x04' + _encode_der_length(len(raw_key)) + raw_key
    inner = b'\x02\x01\x00' + algo_id + priv_key
    return b'\x30' + _encode_der_length(len(inner)) + inner

def _wrap_spki(oid_der, raw_pubkey):
    oid_full = b'\x06' + _encode_der_length(len(oid_der)) + oid_der
    algo_id = b'\x30' + _encode_der_length(len(oid_full)) + oid_full
    content = b'\x00' + raw_pubkey
    bitstring = b'\x03' + _encode_der_length(len(content)) + content
    inner = algo_id + bitstring
    return b'\x30' + _encode_der_length(len(inner)) + inner

def _parse_pkcs8(der_bytes):
    offset = 0
    if der_bytes[offset] != 0x30:
        raise ValueError("非 SEQUENCE")
    length, offset = _decode_der_length(der_bytes, offset + 1)
    if der_bytes[offset:offset + 3] != b'\x02\x01\x00':
        raise ValueError("非 PKCS#8 格式 (缺少版本号)")
    offset += 3
    if der_bytes[offset] != 0x30:
        raise ValueError("非 AlgorithmIdentifier")
    algo_len, offset = _decode_der_length(der_bytes, offset + 1)
    if der_bytes[offset] != 0x06:
        raise ValueError("非 OID")
    oid_len, offset = _decode_der_length(der_bytes, offset + 1)
    oid = der_bytes[offset:offset + oid_len]
    offset += oid_len
    if der_bytes[offset] != 0x04:
        raise ValueError("非 OCTET STRING")
    key_len, offset = _decode_der_length(der_bytes, offset + 1)
    raw_key = der_bytes[offset:offset + key_len]
    return oid, raw_key

def _parse_spki(der_bytes):
    offset = 0
    if der_bytes[offset] != 0x30:
        raise ValueError("非 SEQUENCE")
    length, offset = _decode_der_length(der_bytes, offset + 1)
    if der_bytes[offset] != 0x30:
        raise ValueError("非 AlgorithmIdentifier")
    algo_len, offset = _decode_der_length(der_bytes, offset + 1)
    if der_bytes[offset] != 0x06:
        raise ValueError("非 OID")
    oid_len, offset = _decode_der_length(der_bytes, offset + 1)
    oid = der_bytes[offset:offset + oid_len]
    offset += oid_len
    if der_bytes[offset] != 0x03:
        raise ValueError("非 BIT STRING")
    bits_len, offset = _decode_der_length(der_bytes, offset + 1)
    unused = der_bytes[offset]
    offset += 1
    raw_pubkey = der_bytes[offset:offset + bits_len - 1]
    return oid, raw_pubkey

def _der_to_pem(der_bytes, label="PRIVATE KEY"):
    b64 = base64.b64encode(der_bytes).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"

# ── PQ helpers ─────────────────────────────────────────

def _pq_fn(mod, suffix):
    for name in dir(mod.lib):
        if name.endswith(suffix):
            return getattr(mod.lib, name)
    raise RuntimeError(f"找不到 {mod.__name__} 的 {suffix} 函数")

def _pq_const(mod, suffix):
    for name in dir(mod.lib):
        if name.endswith(suffix):
            return getattr(mod.lib, name)
    raise RuntimeError(f"找不到 {mod.__name__} 的 {suffix} 常量")

def _to_bytes(ffi, buf, length=None):
    return bytes(ffi.buffer(buf)[:length])

def _pq_gen(mod):
    pk_len = _pq_const(mod, "CRYPTO_PUBLICKEYBYTES")
    sk_len = _pq_const(mod, "CRYPTO_SECRETKEYBYTES")
    pk = mod.ffi.new("uint8_t[]", pk_len)
    sk = mod.ffi.new("uint8_t[]", sk_len)
    _pq_fn(mod, "crypto_sign_keypair")(pk, sk)
    return _to_bytes(mod.ffi, pk), _to_bytes(mod.ffi, sk)

def _pq_sign(mod, msg, sk):
    max_sig = _pq_const(mod, "CRYPTO_BYTES")
    sig = mod.ffi.new("uint8_t[]", max_sig)
    siglen = mod.ffi.new("size_t *", 0)
    msg_buf = mod.ffi.new("uint8_t[]", msg)
    _pq_fn(mod, "crypto_sign_signature")(sig, siglen, msg_buf, len(msg), sk)
    return _to_bytes(mod.ffi, sig, siglen[0])

def _pq_verify(mod, sig, msg, pk):
    sig_buf = mod.ffi.new("uint8_t[]", sig)
    msg_buf = mod.ffi.new("uint8_t[]", msg)
    r = _pq_fn(mod, "crypto_sign_verify")(sig_buf, len(sig), msg_buf, len(msg), pk)
    if r != 0:
        raise Exception("验签失败 - 签名无效")

# ══════════════════════════════════════════════════════════

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Proof Of Creation - 本地离线加密算法工具")
        self.root.geometry("900x840")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 0))

        self._build_hash_tab()
        self._build_keygen_tab()
        self._build_pk_from_sk_tab()
        self._build_sign_tab()
        self._build_verify_tab()
        self._build_validate_tab()

        info = ttk.Label(root,
            text="仅支持 PKCS#8 (私钥) / SPKI (公钥) 标准 DER 格式输入输出  |  "
                 "链上Hash = 哈希计算(原文件)  |  链上Signature = 签名(Hash)  |  链上UserID = SHA3-256(公钥)",
            font=("", 8), foreground="gray")
        info.pack(side=tk.BOTTOM, pady=4)

    # ── UI helpers ────────────────────────────────────────

    def _lock_output(self, w):
        w.bind("<Key>", self._block_key)
        w.bind("<<Paste>>", lambda e: "break")
        w.bind("<<Cut>>", lambda e: "break")

    def _block_key(self, e):
        if e.state & 0x4:
            return None
        if e.keysym in ("Control_L", "Control_R", "Shift_L", "Shift_R", "Alt_L", "Alt_R"):
            return None
        return "break"

    def _get_text(self, w):
        return w.get("1.0", tk.END).strip()

    def _parse_raw(self, w, fmt_var):
        raw = self._get_text(w)
        if not raw:
            raise ValueError("输入为空")
        fmt = fmt_var.get()
        if fmt == "hex":
            return bytes.fromhex(raw.replace(" ", "").replace("\n", ""))
        else:
            return base64.b64decode(raw)

    def _detect_private(self, der_bytes):
        try:
            key = serialization.load_der_private_key(der_bytes, password=None)
            if isinstance(key, ed25519.Ed25519PrivateKey):
                return "Ed25519", key.private_bytes_raw()
            if isinstance(key, rsa.RSAPrivateKey):
                return "RSA-2048", der_bytes
        except Exception:
            pass
        oid, raw_key = _parse_pkcs8(der_bytes)
        algo = OID_TO_ALGO.get(oid)
        if algo is None:
            raise ValueError("无法识别的 OID，非标准 PKCS#8 格式")
        if algo not in PQ_ALGOS:
            raise ValueError(f"不支持的算法: {algo}")
        return algo, raw_key

    def _detect_public(self, der_bytes):
        try:
            key = serialization.load_der_public_key(der_bytes)
            if isinstance(key, ed25519.Ed25519PublicKey):
                return "Ed25519", key.public_bytes_raw()
            if isinstance(key, rsa.RSAPublicKey):
                return "RSA-2048", der_bytes
        except Exception:
            pass
        oid, raw_pub = _parse_spki(der_bytes)
        algo = OID_TO_ALGO.get(oid)
        if algo is None:
            raise ValueError("无法识别的 OID，非标准 SPKI 格式")
        if algo not in PQ_ALGOS:
            raise ValueError(f"不支持的算法: {algo}")
        return algo, raw_pub

    def _import_bin(self, w, fmt_var=None):
        path = filedialog.askopenfilename(title="导入文件")
        if not path:
            return
        with open(path, "rb") as f:
            data = f.read()
        if fmt_var is not None:
            fmt_var.set("hex")
        w.delete("1.0", tk.END)
        w.insert("1.0", data.hex())

    def _export_der(self, w):
        raw = self._get_text(w)
        if not raw:
            return
        try:
            data = bytes.fromhex(raw.replace(" ", "").replace("\n", ""))
        except Exception:
            data = base64.b64decode(raw)
        path = filedialog.asksaveasfilename(title="导出 DER 文件", defaultextension=".der")
        if not path:
            return
        with open(path, "wb") as f:
            f.write(data)
        messagebox.showinfo("成功", "已导出 DER")

    def _export_pem(self, w, label="PRIVATE KEY"):
        raw = self._get_text(w)
        if not raw:
            return
        try:
            data = bytes.fromhex(raw.replace(" ", "").replace("\n", ""))
        except Exception:
            data = base64.b64decode(raw)
        pem = _der_to_pem(data, label)
        path = filedialog.asksaveasfilename(title="导出 PEM 文件", defaultextension=".pem")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(pem)
        messagebox.showinfo("成功", "已导出 PEM")

    def _make_io_row(self, parent, row, label, height=4, output=False, pem_label=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.NW, padx=8, pady=4)
        text = tk.Text(parent, height=height)
        text.grid(row=row, column=1, columnspan=3, sticky=tk.NSEW, padx=8, pady=4)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(row, weight=1)
        if output:
            self._lock_output(text)
        btn_frame = ttk.Frame(parent)
        btn_frame.grid(row=row, column=4, sticky=tk.N, padx=4, pady=4)
        if not output:
            ttk.Button(btn_frame, text="导 入\n(文件)", width=8,
                       command=lambda w=text, fv=None: self._import_bin(w, fv)).pack(pady=1)
        else:
            ttk.Button(btn_frame, text="导出DER", width=8,
                       command=lambda w=text: self._export_der(w)).pack(pady=1)
            ttk.Button(btn_frame, text="导出PEM", width=8,
                       command=lambda w=text, lbl=pem_label: self._export_pem(w, lbl)).pack(pady=1)
        return text

    def _make_format_row(self, parent, row, fmt_var):
        ttk.Label(parent, text="输入格式").grid(row=row, column=0, sticky=tk.W, padx=8, pady=4)
        row_frame = ttk.Frame(parent)
        row_frame.grid(row=row, column=1, columnspan=4, sticky=tk.W, padx=8)
        ttk.Radiobutton(row_frame, text="Hex", variable=fmt_var, value="hex").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(row_frame, text="Base64", variable=fmt_var, value="base64").pack(side=tk.LEFT, padx=2)
        return row_frame

    def _fix_import_btn(self, frame, row, widget, fmt_var):
        try:
            btn_frame = frame.grid_slaves(row=row, column=4)[0]
            for child in btn_frame.winfo_children():
                if "导 入" in (child.cget("text") or ""):
                    child.configure(command=lambda w=widget, fv=fmt_var: self._import_bin(w, fv))
        except Exception:
            pass

    def _display_result(self, hex_w, b64_w, raw_bytes):
        hex_w.delete("1.0", tk.END)
        hex_w.insert("1.0", raw_bytes.hex())
        b64_w.delete("1.0", tk.END)
        b64_w.insert("1.0", base64.b64encode(raw_bytes).decode())

    def _hash_data(self, data, algo):
        m = {
            "SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512,
            "SHA3-256": hashlib.sha3_256, "SHA3-512": hashlib.sha3_512,
        }
        if algo in m:
            return m[algo](data).digest()
        if algo == "BLAKE2b-256":
            return hashlib.blake2b(data, digest_size=32).digest()
        if algo == "BLAKE2s-256":
            return hashlib.blake2s(data, digest_size=32).digest()
        return hashlib.sha256(data).digest()

    def _ed25519_extract_seed(self, priv_bytes):
        if len(priv_bytes) == 48:
            try:
                key = serialization.load_der_private_key(priv_bytes, password=None)
                return key.private_bytes_raw()
            except Exception:
                pass
        if len(priv_bytes) == 32:
            return priv_bytes
        if len(priv_bytes) == 64:
            return priv_bytes[:32]
        if len(priv_bytes) == 96:
            return priv_bytes[:32]
        raise ValueError(f"Ed25519 私钥应为 32/48/64/96 字节，实际 {len(priv_bytes)}")

    # ════════ 哈希计算 ═════════════════════════════════════

    def _build_hash_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="哈希计算")

        self.hash_fmt = tk.StringVar(value="hex")
        self.hash_algo = tk.StringVar(value=HASH_ALGOS[0])

        rf = self._make_format_row(frame, 0, self.hash_fmt)
        ttk.Label(rf, text="  算法").pack(side=tk.LEFT, padx=(16, 2))
        combo = ttk.Combobox(rf, textvariable=self.hash_algo, values=HASH_ALGOS, state="readonly", width=20)
        combo.pack(side=tk.LEFT, padx=2)
        combo.set(HASH_ALGOS[0])

        self.hash_input = self._make_io_row(frame, 1, "数据", height=5)
        self._fix_import_btn(frame, 1, self.hash_input, self.hash_fmt)

        ttk.Button(frame, text="计算哈希", command=self._compute_hash).grid(row=2, column=1, sticky=tk.W, padx=8, pady=8)

        self.hash_hex_out = self._make_io_row(frame, 3, "HEX 结果", height=3, output=True)
        self.hash_b64_out = self._make_io_row(frame, 4, "Base64 结果", height=3, output=True)

        frame.columnconfigure(1, weight=1)
        for r in range(5):
            frame.rowconfigure(r, weight=1 if r in (1, 3, 4) else 0)

    def _compute_hash(self):
        try:
            data = self._parse_raw(self.hash_input, self.hash_fmt)
        except Exception as e:
            messagebox.showerror("错误", f"输入解析失败: {e}")
            return
        algo = self.hash_algo.get()
        digest = self._hash_data(data, algo)
        self._display_result(self.hash_hex_out, self.hash_b64_out, digest)

    # ════════ 密钥生成 ═════════════════════════════════════

    def _build_keygen_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="密钥生成")

        ttk.Label(frame, text="算法").grid(row=0, column=0, sticky=tk.W, padx=8, pady=4)
        rf = ttk.Frame(frame)
        rf.grid(row=0, column=1, columnspan=4, sticky=tk.W, padx=8)
        self.kg_algo = tk.StringVar(value=KEY_ALGOS[0])
        combo = ttk.Combobox(rf, textvariable=self.kg_algo, values=KEY_ALGOS, state="readonly", width=22)
        combo.pack(side=tk.LEFT, padx=2)
        combo.set(KEY_ALGOS[0])
        ttk.Button(rf, text="生成密钥对", command=self._do_keygen).pack(side=tk.LEFT, padx=(16, 0))

        self.kg_priv_hex = self._make_io_row(frame, 1, "私钥 (PKCS#8 HEX)", height=3, output=True, pem_label="PRIVATE KEY")
        self.kg_priv_b64 = self._make_io_row(frame, 2, "私钥 (PKCS#8 B64)", height=3, output=True, pem_label="PRIVATE KEY")
        self.kg_pub_hex  = self._make_io_row(frame, 3, "公钥 (SPKI HEX)",  height=3, output=True, pem_label="PUBLIC KEY")
        self.kg_pub_b64  = self._make_io_row(frame, 4, "公钥 (SPKI B64)",  height=3, output=True, pem_label="PUBLIC KEY")

        ttk.Label(frame, text="UserID  (SHA3-256)").grid(row=5, column=0, sticky=tk.NW, padx=8, pady=4)
        self.kg_userid = tk.Text(frame, height=2)
        self.kg_userid.grid(row=5, column=1, columnspan=3, sticky=tk.NSEW, padx=8, pady=4)
        self._lock_output(self.kg_userid)
        frame.rowconfigure(5, weight=1)

        frame.columnconfigure(1, weight=1)
        for r in range(6):
            frame.rowconfigure(r, weight=1 if r in (1, 2, 3, 4, 5) else 0)

    def _do_keygen(self):
        algo = self.kg_algo.get()
        try:
            if algo == "Ed25519":
                priv = ed25519.Ed25519PrivateKey.generate()
                raw_pub = priv.public_key().public_bytes_raw()
                priv_der = priv.private_bytes(serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                pub_der = priv.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
            elif algo == "RSA-2048":
                priv = rsa.generate_private_key(65537, 2048)
                raw_pub = priv.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                priv_der = priv.private_bytes(serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                pub_der = raw_pub
            elif algo in PQ_ALGOS:
                raw_pub, raw_sk = _pq_gen(PQ_ALGOS[algo])
                oid = ALGO_TO_OID[algo]
                priv_der = _wrap_pkcs8(oid, raw_sk)
                pub_der = _wrap_spki(oid, raw_pub)
            else:
                return messagebox.showerror("错误", f"不支持的算法: {algo}")

            self._display_result(self.kg_priv_hex, self.kg_priv_b64, priv_der)
            self._display_result(self.kg_pub_hex, self.kg_pub_b64, pub_der)

            uid = hashlib.sha3_256(raw_pub if algo != "RSA-2048" else pub_der).digest()
            self.kg_userid.delete("1.0", tk.END)
            self.kg_userid.insert("1.0", uid.hex())
            self.kg_userid.insert(tk.END, f"\n{base64.b64encode(uid).decode()}")

            parts = [f"{algo} 密钥对已生成"]
            if algo in DRAFT_OID_ALGOS:
                parts.append("⚠ 该算法 OID 为草案值，未来可能变更")
            if algo in NO_DERIVE_ALGOS:
                parts.append("⚠ 该算法不支持从私钥恢复公钥，请务必同时保存公钥")
            messagebox.showinfo("成功", "\n".join(parts) + "\n\n请妥善保存私钥！")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ════════ 生成公钥 ═════════════════════════════════════

    def _build_pk_from_sk_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="生成公钥")

        self.pk_fmt = tk.StringVar(value="hex")
        self._make_format_row(frame, 0, self.pk_fmt)

        self.pk_priv_in = self._make_io_row(frame, 1, "私钥 (PKCS#8)", height=5)
        self._fix_import_btn(frame, 1, self.pk_priv_in, self.pk_fmt)

        self.pk_detect = ttk.Label(frame, text="", foreground="gray")
        self.pk_detect.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=8)

        ttk.Button(frame, text="生成公钥", command=self._do_pk_from_sk).grid(row=3, column=1, sticky=tk.W, padx=8, pady=4)

        self.pk_pub_hex = self._make_io_row(frame, 4, "公钥 (SPKI HEX)",  height=3, output=True, pem_label="PUBLIC KEY")
        self.pk_pub_b64 = self._make_io_row(frame, 5, "公钥 (SPKI B64)",  height=3, output=True, pem_label="PUBLIC KEY")

        ttk.Label(frame, text="UserID  (SHA3-256)").grid(row=6, column=0, sticky=tk.NW, padx=8, pady=4)
        self.pk_userid = tk.Text(frame, height=2)
        self.pk_userid.grid(row=6, column=1, columnspan=3, sticky=tk.NSEW, padx=8, pady=4)
        self._lock_output(self.pk_userid)
        frame.rowconfigure(6, weight=1)

        self.pk_hint = ttk.Label(frame, text="", foreground="red")
        self.pk_hint.grid(row=7, column=1, columnspan=3, sticky=tk.W, padx=8, pady=2)

        frame.columnconfigure(1, weight=1)
        for r in range(8):
            frame.rowconfigure(r, weight=1 if r in (1, 4, 5, 6) else 0)

        self.pk_priv_in.bind("<KeyRelease>", lambda e: self._on_pk_input_change())
        self._on_pk_input_change()

    def _on_pk_input_change(self):
        raw = self._get_text(self.pk_priv_in)
        self.pk_detect.config(text="")
        self.pk_hint.config(text="")
        if not raw:
            return
        try:
            der = self._parse_raw(self.pk_priv_in, self.pk_fmt)
            algo, _ = self._detect_private(der)
            if algo in NO_DERIVE_ALGOS:
                self.pk_hint.config(text=f"{algo} 不支持从私钥生成公钥，请在\"密钥生成\"页重新生成密钥对并妥善保存")
                self.pk_detect.config(text=f"已检测: {algo}", foreground="red")
            else:
                self.pk_detect.config(text=f"已检测: {algo}", foreground="green")
        except Exception:
            pass

    def _do_pk_from_sk(self):
        try:
            der = self._parse_raw(self.pk_priv_in, self.pk_fmt)
            algo, raw_key = self._detect_private(der)

            if algo in NO_DERIVE_ALGOS:
                return messagebox.showerror("错误",
                    f"{algo} 不支持从私钥生成公钥，请在\"密钥生成\"页重新生成密钥对并妥善保存")

            if algo == "Ed25519":
                seed = self._ed25519_extract_seed(der)
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                raw_pub = priv.public_key().public_bytes_raw()
                pub_der = priv.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                return messagebox.showerror("错误", f"{algo} 不支持从私钥生成公钥")

            self._display_result(self.pk_pub_hex, self.pk_pub_b64, pub_der)

            uid = hashlib.sha3_256(raw_pub).digest()
            self.pk_userid.delete("1.0", tk.END)
            self.pk_userid.insert("1.0", uid.hex())
            self.pk_userid.insert(tk.END, f"\n{base64.b64encode(uid).decode()}")

            messagebox.showinfo("成功", "已从私钥生成公钥")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ════════ 签名 ═════════════════════════════════════════

    def _build_sign_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="签名")

        self.sign_fmt = tk.StringVar(value="hex")
        rf = self._make_format_row(frame, 0, self.sign_fmt)

        self.sign_algo_label = ttk.Label(rf, text="")
        self.sign_algo_label.pack(side=tk.LEFT, padx=(16, 2))
        self.sign_rsa_hash = tk.StringVar(value="SHA256")
        self.sign_rsa_cb = ttk.Combobox(rf, textvariable=self.sign_rsa_hash,
            values=["SHA256", "SHA512"], state="readonly", width=8)

        self.sign_data = self._make_io_row(frame, 1, "数据 (hash)", height=5)
        self._fix_import_btn(frame, 1, self.sign_data, self.sign_fmt)

        self.sign_privkey = self._make_io_row(frame, 2, "私钥 (PKCS#8)", height=5)
        self._fix_import_btn(frame, 2, self.sign_privkey, self.sign_fmt)

        self.sign_detect = ttk.Label(frame, text="", foreground="gray")
        self.sign_detect.grid(row=3, column=1, columnspan=3, sticky=tk.W, padx=8)

        ttk.Button(frame, text="签名", command=self._do_sign).grid(row=4, column=1, sticky=tk.W, padx=8, pady=8)

        self.sign_hex_out = self._make_io_row(frame, 5, "签名 (HEX)", height=3, output=True)
        self.sign_b64_out = self._make_io_row(frame, 6, "签名 (Base64)", height=3, output=True)

        frame.columnconfigure(1, weight=1)
        for r in range(7):
            frame.rowconfigure(r, weight=1 if r in (1, 2, 5, 6) else 0)

        self.sign_rsa_cb.pack_forget()
        self.sign_privkey.bind("<KeyRelease>", lambda e: self._on_sign_key_change())
        self._on_sign_key_change()

    def _on_sign_key_change(self):
        raw = self._get_text(self.sign_privkey)
        self.sign_detect.config(text="")
        self.sign_algo_label.config(text="")
        self.sign_rsa_cb.pack_forget()
        if not raw:
            return
        try:
            der = self._parse_raw(self.sign_privkey, self.sign_fmt)
            algo, _ = self._detect_private(der)
            self.sign_detect.config(text=f"已检测: {algo}", foreground="green")
            if algo == "RSA-2048":
                self.sign_algo_label.config(text="  RSA哈希:")
                self.sign_rsa_cb.pack(side=tk.LEFT, padx=2)
        except Exception:
            self.sign_detect.config(text="非标准私钥格式", foreground="red")

    def _do_sign(self):
        try:
            data = self._parse_raw(self.sign_data, self.sign_fmt)
            der = self._parse_raw(self.sign_privkey, self.sign_fmt)
            algo, raw_key = self._detect_private(der)

            if algo == "Ed25519":
                seed = self._ed25519_extract_seed(der)
                sig = ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(data)
            elif algo == "RSA-2048":
                hash_alg = hashes.SHA256() if self.sign_rsa_hash.get() == "SHA256" else hashes.SHA512()
                sig = serialization.load_der_private_key(der, password=None).sign(
                    data, padding.PKCS1v15(), hash_alg)
            elif algo in PQ_ALGOS:
                sig = _pq_sign(PQ_ALGOS[algo], data, raw_key)
            else:
                return messagebox.showerror("错误", f"不支持的算法: {algo}")

            self._display_result(self.sign_hex_out, self.sign_b64_out, sig)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ════════ 验签 ═════════════════════════════════════════

    def _build_verify_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="验签")

        self.verify_fmt = tk.StringVar(value="hex")
        rf = self._make_format_row(frame, 0, self.verify_fmt)

        self.verify_algo_label = ttk.Label(rf, text="")
        self.verify_algo_label.pack(side=tk.LEFT, padx=(16, 2))
        self.verify_rsa_hash = tk.StringVar(value="SHA256")
        self.verify_rsa_cb = ttk.Combobox(rf, textvariable=self.verify_rsa_hash,
            values=["SHA256", "SHA512"], state="readonly", width=8)

        self.verify_data = self._make_io_row(frame, 1, "数据 (hash)", height=4)
        self._fix_import_btn(frame, 1, self.verify_data, self.verify_fmt)

        self.verify_pubkey = self._make_io_row(frame, 2, "公钥 (SPKI)", height=4)
        self._fix_import_btn(frame, 2, self.verify_pubkey, self.verify_fmt)

        self.verify_sig = self._make_io_row(frame, 3, "签名", height=4)
        self._fix_import_btn(frame, 3, self.verify_sig, self.verify_fmt)

        self.verify_detect = ttk.Label(frame, text="", foreground="gray")
        self.verify_detect.grid(row=4, column=1, columnspan=3, sticky=tk.W, padx=8)

        ttk.Button(frame, text="验签", command=self._do_verify).grid(row=5, column=1, sticky=tk.W, padx=8, pady=8)

        self.verify_result = ttk.Label(frame, text="", font=("", 12, "bold"))
        self.verify_result.grid(row=6, column=1, sticky=tk.W, padx=8, pady=4)

        frame.columnconfigure(1, weight=1)
        for r in range(7):
            frame.rowconfigure(r, weight=1 if r in (1, 2, 3) else 0)

        self.verify_rsa_cb.pack_forget()
        self.verify_pubkey.bind("<KeyRelease>", lambda e: self._on_verify_key_change())
        self._on_verify_key_change()

    def _on_verify_key_change(self):
        raw = self._get_text(self.verify_pubkey)
        self.verify_detect.config(text="")
        self.verify_algo_label.config(text="")
        self.verify_rsa_cb.pack_forget()
        if not raw:
            return
        try:
            der = self._parse_raw(self.verify_pubkey, self.verify_fmt)
            algo, _ = self._detect_public(der)
            self.verify_detect.config(text=f"已检测: {algo}", foreground="green")
            if algo == "RSA-2048":
                self.verify_algo_label.config(text="  RSA哈希:")
                self.verify_rsa_cb.pack(side=tk.LEFT, padx=2)
        except Exception:
            self.verify_detect.config(text="非标准公钥格式", foreground="red")

    def _do_verify(self):
        try:
            data = self._parse_raw(self.verify_data, self.verify_fmt)
            sig = self._parse_raw(self.verify_sig, self.verify_fmt)
            der = self._parse_raw(self.verify_pubkey, self.verify_fmt)
            algo, raw_pub = self._detect_public(der)

            if algo == "Ed25519":
                ed25519.Ed25519PublicKey.from_public_bytes(raw_pub).verify(sig, data)
            elif algo == "RSA-2048":
                hash_alg = hashes.SHA256() if self.verify_rsa_hash.get() == "SHA256" else hashes.SHA512()
                serialization.load_der_public_key(der).verify(
                    sig, data, padding.PKCS1v15(), hash_alg)
            elif algo in PQ_ALGOS:
                _pq_verify(PQ_ALGOS[algo], sig, data, raw_pub)
            else:
                return messagebox.showerror("错误", f"不支持的算法: {algo}")

            self.verify_result.config(text="验签成功", foreground="green")
        except Exception as e:
            self.verify_result.config(text=f"验签失败: {e}", foreground="red")

    # ════════ 验证公私钥对 ═════════════════════════════════

    def _build_validate_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="验证公私钥对")

        self.val_fmt = tk.StringVar(value="hex")
        self._make_format_row(frame, 0, self.val_fmt)

        self.val_pubkey = self._make_io_row(frame, 1, "公钥 (SPKI)", height=4)
        self._fix_import_btn(frame, 1, self.val_pubkey, self.val_fmt)

        self.val_privkey = self._make_io_row(frame, 2, "私钥 (PKCS#8)", height=4)
        self._fix_import_btn(frame, 2, self.val_privkey, self.val_fmt)

        self.val_detect = ttk.Label(frame, text="", foreground="gray")
        self.val_detect.grid(row=3, column=1, columnspan=3, sticky=tk.W, padx=8)

        ttk.Button(frame, text="验证", command=self._do_validate).grid(row=4, column=1, sticky=tk.W, padx=8, pady=8)

        self.val_result = ttk.Label(frame, text="", font=("", 12, "bold"))
        self.val_result.grid(row=5, column=1, sticky=tk.W, padx=8, pady=4)

        frame.columnconfigure(1, weight=1)
        for r in range(6):
            frame.rowconfigure(r, weight=1 if r in (1, 2) else 0)

        self.val_pubkey.bind("<KeyRelease>", lambda e: self._on_val_input_change())
        self.val_privkey.bind("<KeyRelease>", lambda e: self._on_val_input_change())
        self._on_val_input_change()

    def _on_val_input_change(self):
        pub_raw = self._get_text(self.val_pubkey)
        priv_raw = self._get_text(self.val_privkey)
        self.val_detect.config(text="")
        if not pub_raw and not priv_raw:
            return
        parts = []
        if pub_raw:
            try:
                der = self._parse_raw(self.val_pubkey, self.val_fmt)
                a, _ = self._detect_public(der)
                parts.append(f"公钥: {a}")
            except Exception:
                parts.append("公钥: 非标准格式")
        if priv_raw:
            try:
                der = self._parse_raw(self.val_privkey, self.val_fmt)
                a, _ = self._detect_private(der)
                parts.append(f"私钥: {a}")
            except Exception:
                parts.append("私钥: 非标准格式")
        self.val_detect.config(text="  |  ".join(parts))

    def _do_validate(self):
        try:
            pub_der = self._parse_raw(self.val_pubkey, self.val_fmt)
            priv_der = self._parse_raw(self.val_privkey, self.val_fmt)
            pub_algo, raw_pub = self._detect_public(pub_der)
            priv_algo, raw_priv = self._detect_private(priv_der)

            if pub_algo.replace("SHA256with", "").replace("SHA512with", "") != priv_algo:
                return messagebox.showerror("错误",
                    f"算法不匹配: 公钥={pub_algo}, 私钥={priv_algo}")

            test_data = b"PoC_keypair_validation"

            if pub_algo == "Ed25519":
                seed = self._ed25519_extract_seed(priv_der)
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                pub = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
                pub.verify(priv.sign(test_data), test_data)
            elif pub_algo == "RSA-2048":
                priv = serialization.load_der_private_key(priv_der, password=None)
                pub = serialization.load_der_public_key(pub_der)
                sig = priv.sign(test_data, padding.PKCS1v15(), hashes.SHA256())
                pub.verify(sig, test_data, padding.PKCS1v15(), hashes.SHA256())
            elif pub_algo in PQ_ALGOS:
                sig = _pq_sign(PQ_ALGOS[pub_algo], test_data, raw_priv)
                _pq_verify(PQ_ALGOS[pub_algo], sig, test_data, raw_pub)
            else:
                return messagebox.showerror("错误", f"不支持的算法: {pub_algo}")

            self.val_result.config(text="匹配 - 公私钥对正确", foreground="green")
        except Exception as e:
            self.val_result.config(text=f"不匹配: {e}", foreground="red")


def main():
    root = tk.Tk()
    CryptoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
