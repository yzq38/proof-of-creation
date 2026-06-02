// ===================================================================
// Proof Of Creation - 客户端加密
// SHA3-256: @std/crypto / Ed25519: Web Crypto API
// ===================================================================
import { crypto as stdCrypto } from "https://esm.sh/jsr/@std/crypto@1.1.0";

window.sha3Ready = true;

// --- Ed25519 检测 (原生 Web Crypto API) ---
window.ed25519Supported = false;
window.ed25519Ready = false;

window._ed25519Promise = (async function () {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    window.ed25519Supported = true;
  } catch (e) {
    window.ed25519Supported = false;
  }
  window.ed25519Ready = true;
  var el = document.getElementById("detect-ed");
  if (el) el.textContent = window.ed25519Supported ? "支持" : "不支持";
})();

// --- 编码工具 ---
window.u8_to_hex = function (u8) {
  var s = "";
  for (var i = 0; i < u8.length; i++) {
    var b = u8[i];
    s += (b >> 4).toString(16) + (b & 15).toString(16);
  }
  return s;
};

window.hex_to_u8 = function (hex) {
  hex = hex.replace(/\s/g, "");
  var n = hex.length >> 1;
  var u8 = new Uint8Array(n);
  for (var i = 0; i < n; i++) u8[i] = parseInt(hex.substr(i * 2, 2), 16);
  return u8;
};

window.u8_to_base64 = function (u8) {
  var bin = "";
  for (var i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
};

function u8_to_base64url(u8) {
  return btoa(String.fromCharCode.apply(null, u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

window.base64_to_u8 = function (b64) {
  var bin = atob(b64);
  var u8 = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
};

window.base64_to_hex = function (b64) {
  return u8_to_hex(window.base64_to_u8(b64));
};

// --- SHA3-256 (@std/crypto) ---
window.sha3_256 = async function (data) {
  return await stdCrypto.subtle.digest("SHA3-256", data);
};

window.sha3_256_hex = async function (data) {
  var hash = await stdCrypto.subtle.digest("SHA3-256", data);
  return u8_to_hex(new Uint8Array(hash));
};

// --- Ed25519 (原生 Web Crypto API) ---
window.generate_ed25519_key = async function () {
  return await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
};

window.export_public_key = async function (key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
};

window.export_private_key = async function (key) {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
};

window.import_private_key = async function (rawBytes) {
  if (rawBytes instanceof Uint8Array) {
    var str = new TextDecoder().decode(rawBytes);
    var m = str.match(/-----BEGIN [A-Z ]+-----\r?\n?([\s\S]+?)-----END [A-Z ]+-----/);
    if (m) {
      rawBytes = base64_to_u8(m[1].replace(/[\r\n\s]/g, ''));
    }
  }
  try {
    return await crypto.subtle.importKey(
      "pkcs8", rawBytes, { name: "Ed25519" }, true, ["sign"]
    );
  } catch (e) {}
  try {
    var d = u8_to_base64url(rawBytes);
    var jwk = { kty: "OKP", crv: "Ed25519", d: d };
    return await crypto.subtle.importKey(
      "jwk", jwk, { name: "Ed25519" }, true, ["sign"]
    );
  } catch (e) {}
  throw new Error("无法导入私钥，请确认格式正确 (PKCS#8 DER/PEM)");
};

window.derive_public_key = async function (privateKey) {
  var jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" },
    true,
    ["verify"]
  );
};

window.sign_ed25519 = async function (privateKey, data) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data));
};

// --- 文件哈希 ---
window.hash_file = async function (file) {
  return new Promise(function (resolve, reject) {
    var reader = new FileReader();
    reader.onload = async function (e) {
      var u8 = new Uint8Array(e.target.result);
      var hash = await sha3_256(u8);
      resolve({ hash: new Uint8Array(hash), hex: u8_to_hex(new Uint8Array(hash)) });
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
};
