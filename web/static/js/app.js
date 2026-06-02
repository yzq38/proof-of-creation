const API_BASE = "/api";
let token = localStorage.getItem("poc_token") || null;
let currentUser = { user_name: localStorage.getItem("poc_username") || "" };

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function auth_header() {
  return token ? { "Authorization": "Bearer " + token, "Content-Type": "application/json" } : { "Content-Type": "application/json" };
}

async function api(method, path, body) {
  const opts = { method, headers: auth_header() };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(API_BASE + path, opts);
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || "请求失败");
  return data;
}

function $(id) { return document.getElementById(id); }

function show_section(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
  const el = $(id);
  if (el) el.classList.remove("hidden");
}

function show_alert(id, type, msg) {
  const el = $(id);
  if (!el) return;
  el.className = "alert alert-" + type;
  el.textContent = msg;
  el.classList.remove("hidden");
}

function hide_alert(id) {
  const el = $(id);
  if (el) el.classList.add("hidden");
}

function format_time(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

function format_cny(v) {
  if (v == null) return "-";
  return parseFloat(v).toFixed(2) + " CNY";
}

function html_status(status) {
  const map = {
    "pending": '<span class="status-tag status-pending">待支付</span>',
    "paid": '<span class="status-tag status-paid">已支付</span>',
    "onchain": '<span class="status-tag status-onchain">上链中</span>',
    "success": '<span class="status-tag status-success">成功</span>',
    "cancelled": '<span class="status-tag status-cancelled">已取消</span>',
    "refunded": '<span class="status-tag status-refunded">已退款</span>',
  };
  return map[status] || status;
}

function update_nav() {
  const loggedIn = !!token;
  $("nav-guest").classList.toggle("hidden", loggedIn);
  $("nav-user").classList.toggle("hidden", !loggedIn);
  if (loggedIn && currentUser && currentUser.user_name) {
    $("nav-username").textContent = currentUser.user_name;
  }
}

function logout() {
  token = null;
  currentUser = null;
  localStorage.removeItem("poc_token");
  localStorage.removeItem("poc_username");
  update_nav();
  show_section("section-login");
}

async function handle_login(e) {
  e.preventDefault();
  hide_alert("login-alert");
  const user_name = $("login-username").value.trim();
  const password = $("login-password").value;
  try {
    const data = await api("POST", "/auth/login", { user_name, password });
    token = data.token;
    currentUser = data;
    localStorage.setItem("poc_token", token);
    localStorage.setItem("poc_username", data.user_name);
    update_nav();
    show_section("section-dashboard");
    load_dashboard();
  } catch (err) {
    show_alert("login-alert", "error", err.message);
  }
}

async function handle_register(e) {
  e.preventDefault();
  hide_alert("register-alert");
  const user_name = $("register-username").value.trim();
  const password = $("register-password").value;
  if (password.length < 6) {
    show_alert("register-alert", "error", "密码长度至少6个字符");
    return;
  }
  try {
    const data = await api("POST", "/auth/register", { user_name, password });
    token = data.token;
    currentUser = data;
    localStorage.setItem("poc_token", token);
    localStorage.setItem("poc_username", data.user_name);
    update_nav();
    show_section("section-dashboard");
    load_dashboard();
  } catch (err) {
    show_alert("register-alert", "error", err.message);
  }
}

async function load_dashboard() {
  try {
    const balance = await api("GET", "/user/balance");
    $("dashboard-balance").textContent = balance.balance.toFixed(2) + " CNY";
    $("dash-balance-input").value = "";
    const orders = await api("GET", "/orders");
    render_dash_orders(orders);
  } catch (err) {
    console.error(err);
  }
}

function render_dash_orders(orders) {
  const tbody = $("dash-orders-tbody");
  tbody.innerHTML = orders.slice(0, 5).map(o => `
    <tr>
      <td>${o.order_id}</td>
      <td>${esc(o.file_name)}</td>
      <td>${o.encryption_mode}</td>
      <td>${html_status(o.status)}</td>
      <td>${format_cny(o.paid_amount)}</td>
      <td>${format_time(o.created_at)}</td>
    </tr>
  `).join("") || '<tr><td colspan="6" style="text-align:center">暂无订单</td></tr>';
}

async function handle_quick_deposit() {
  const amount = parseFloat($("dash-balance-input").value);
  if (!amount || amount <= 0) {
    show_alert("dash-alert", "error", "请输入有效金额");
    return;
  }
  try {
    const data = await api("POST", "/user/deposit", { amount });
    $("dashboard-balance").textContent = data.balance.toFixed(2) + " CNY";
    $("dash-balance-input").value = "";
    show_alert("dash-alert", "success", "储值成功: " + amount.toFixed(2) + " CNY");
  } catch (err) {
    show_alert("dash-alert", "error", err.message);
  }
}

async function handle_quick_withdraw() {
  const amount = parseFloat($("dash-balance-input").value);
  if (!amount || amount <= 0) {
    show_alert("dash-alert", "error", "请输入有效金额");
    return;
  }
  try {
    const data = await api("POST", "/user/withdraw", { amount });
    $("dashboard-balance").textContent = data.balance.toFixed(2) + " CNY";
    $("dash-balance-input").value = "";
    show_alert("dash-alert", "success", "提现成功: " + amount.toFixed(2) + " CNY");
  } catch (err) {
    show_alert("dash-alert", "error", err.message);
  }
}

let order_file = null;
let order_hash_hex = "";
let order_hash_u8 = null;
let current_key = null;
let order_encryption_mode = "";
let current_create_mode = "default";

function switch_mode(mode) {
  current_create_mode = mode;
  $("btn-mode-default").className = mode === "default" ? "btn btn-primary" : "btn btn-outline";
  $("btn-mode-advanced").className = mode === "advanced" ? "btn btn-primary" : "btn btn-outline";
  $("create-mode-default").classList.toggle("hidden", mode !== "default");
  $("create-mode-advanced").classList.toggle("hidden", mode !== "advanced");
}

function create_current_mode(e) {
  e.preventDefault();
  if (current_create_mode === "advanced") {
    handle_create_order_advanced(e);
  } else {
    handle_create_order_default(e);
  }
}

async function show_create_order() {
  if (!ed25519Ready) await _ed25519Promise;
  ed25519Supported ? show_section("section-create-default") : show_section("section-create-basic");
}

async function handle_file_select(e) {
  order_file = e.target.files[0];
  if (!order_file) return;
  $("create-file-name").textContent = order_file.name;
  $("create-file-name").classList.remove("hidden");
  $("create-file-hint").classList.add("hidden");

  const result = await hash_file(order_file);
  order_hash_u8 = result.hash;
  order_hash_hex = u8_to_hex(order_hash_u8);
  $("create-hash-display").textContent = u8_to_base64(order_hash_u8);
  $("create-hash-display").classList.remove("hidden");

  let displayName = order_file.name + "_sha3-256_ed25519";
  if (displayName.length > 32) displayName = order_file.name.substring(0, 20) + "_sha3-256_ed25519";
  $("create-file-name-input").value = displayName.substring(0, 32);
}

async function handle_generate_key() {
  try {
    current_key = await generate_ed25519_key();
    const pub_u8 = await export_public_key(current_key);
    $("create-pubkey-display").textContent = u8_to_base64(pub_u8);
    $("create-pubkey-label").classList.remove("hidden");
    $("create-pubkey-display").classList.remove("hidden");

    const priv_u8 = await export_private_key(current_key);
    $("create-privkey-display").textContent = u8_to_base64(priv_u8);
    $("create-privkey-label").classList.remove("hidden");
    $("create-privkey-display").classList.remove("hidden");
  } catch (err) {
    show_alert("create-alert", "error", "密钥生成失败: " + err.message);
  }
}

async function handle_import_key() {
  var priv_b64 = ($("create-import-privkey").value || "").trim();
  if (!priv_b64) {
    show_alert("create-alert", "error", "请粘贴私钥 (base64)");
    return;
  }
  try {
    var raw = base64_to_u8(priv_b64);
    var privateKey = await import_private_key(raw);
    var pubKey = await derive_public_key(privateKey);
    var pub_u8 = new Uint8Array(await crypto.subtle.exportKey("raw", pubKey));

    current_key = { privateKey: privateKey, publicKey: pubKey };
    $("create-pubkey-display").textContent = u8_to_base64(pub_u8);
    $("create-pubkey-label").classList.remove("hidden");
    $("create-pubkey-display").classList.remove("hidden");
    $("create-privkey-display").textContent = priv_b64;
    $("create-privkey-label").classList.remove("hidden");
    $("create-privkey-display").classList.remove("hidden");
    show_alert("create-alert", "success", "私钥导入成功");
  } catch (err) {
    show_alert("create-alert", "error", "私钥导入失败: " + err.message);
  }
}

async function handle_create_order_default(e) {
  e.preventDefault();
  if (!order_file || !order_hash_u8) {
    show_alert("create-alert", "error", "请先选择文件");
    return;
  }
  if (!current_key) {
    show_alert("create-alert", "error", "请先生成或导入密钥");
    return;
  }

  try {
    const sig = await sign_ed25519(current_key.privateKey, order_hash_u8);
    const sig_hex = u8_to_hex(sig);
    const pub_u8 = await export_public_key(current_key);
    const user_id_buf = await sha3_256(pub_u8);
    const user_id_hex = u8_to_hex(new Uint8Array(user_id_buf));

    $("create-confirm-hash").textContent = u8_to_base64(order_hash_u8);
    $("create-confirm-sig").textContent = u8_to_base64(sig);
    $("create-confirm-pub").textContent = u8_to_base64(pub_u8);
    $("create-confirm-userid").textContent = u8_to_base64(new Uint8Array(user_id_buf));

    order_encryption_mode = "sha3-256+ed25519";
    $("create-confirm-modal").classList.add("active");

    window._order_chain_data = {
      hash: u8_to_hex(order_hash_u8),
      signature1: sig_hex.substring(0, 64),
      signature2: sig_hex.substring(64),
      user_id: user_id_hex,
      sig_full: sig_hex
    };
  } catch (err) {
    show_alert("create-alert", "error", "签名失败: " + err.message);
  }
}

async function handle_create_order_advanced(e) {
  e.preventDefault();
  hide_alert("create-alert");
  $("adv-size-warn").classList.add("hidden");

  var pub_b64 = ($("adv-pubkey").value || "").trim();
  var hash_b64 = ($("adv-hash").value || "").trim();
  var sig_b64 = ($("adv-sig").value || "").trim();

  if (!pub_b64 || !hash_b64 || !sig_b64) {
    show_alert("create-alert", "error", "请填写公钥、哈希和签名 (base64)");
    return;
  }

  try {
    var pub_u8 = base64_to_u8(pub_b64);
    var hash_u8 = base64_to_u8(hash_b64);
    var sig_u8 = base64_to_u8(sig_b64);

    var total_size = hash_u8.length + sig_u8.length + 32;
    if (total_size > 512) {
      $("adv-size-warn").classList.remove("hidden");
    }

    var pub_hex = u8_to_hex(pub_u8);
    var hash_hex = u8_to_hex(hash_u8);
    var sig_hex = u8_to_hex(sig_u8);
    var user_id_buf = await sha3_256(pub_u8);
    var user_id_hex = u8_to_hex(new Uint8Array(user_id_buf));

    $("create-confirm-hash").textContent = hash_b64;
    $("create-confirm-sig").textContent = sig_b64;
    $("create-confirm-pub").textContent = pub_b64;
    $("create-confirm-userid").textContent = u8_to_base64(new Uint8Array(user_id_buf));

    order_encryption_mode = "advanced";
    $("create-confirm-modal").classList.add("active");

    window._order_chain_data = {
      hash: hash_hex,
      signature: sig_hex,
      user_id: user_id_hex
    };
  } catch (err) {
    show_alert("create-alert", "error", "数据解析失败: " + err.message);
  }
}

async function handle_create_order() {
  $("create-confirm-modal").classList.remove("active");
  hide_alert("create-alert");

  const btnConfirm = $("btn-confirm-create");
  const btnMain = $("btn-main-create");
  btnConfirm.disabled = true;
  btnConfirm.classList.add("btn-loading");
  btnConfirm.textContent = "创建中...";
  btnMain.disabled = true;
  btnMain.classList.add("btn-loading");
  btnMain.textContent = "创建中...";

  try {
    const ch = window._order_chain_data;
    const hash_len = ch.hash.length / 2;
    const sig_len = order_encryption_mode === "advanced" ? (ch.signature.length / 2) : 0;
    const order = await api("POST", "/orders/create", {
      file_name: current_create_mode === "advanced" ? ($("adv-file-name").value || "untitled") : ($("create-file-name-input").value || "untitled"),
      encryption_mode: order_encryption_mode,
      hash_len: hash_len,
      sig_len: sig_len,
      gas_multiplier: parseFloat($("create-gas-multiplier").value) || 1.2
    });

    $("create-pricing").classList.remove("hidden");
    $("create-price-display").textContent = order.payment_price.toFixed(2) + " CNY";
    $("create-gas-limit").textContent = order.gas_limit_adjusted;
    $("create-gas-price").textContent = (order.gas_price_wei / 1e9).toFixed(2) + " Gwei";
    $("create-rate").textContent = order.exchange_rate.toFixed(2);
    $("create-expiry").textContent = order.order_expiry + "秒";

    window._current_order = order;
    $("create-pay-section").classList.remove("hidden");
    $("pay-price-display").textContent = order.payment_price.toFixed(2) + " CNY";
    show_alert("create-alert", "success", "订单已创建，有效期" + order.order_expiry + "秒");

    $("create-pricing").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    show_alert("create-alert", "error", "创建订单失败: " + err.message);
  }

  btnConfirm.disabled = false;
  btnConfirm.classList.remove("btn-loading");
  btnConfirm.textContent = "确认无误，创建订单";
  btnMain.disabled = false;
  btnMain.classList.remove("btn-loading");
  btnMain.textContent = "创建订单";
}

async function handle_pay_order() {
  if (!window._current_order || !window._order_chain_data) return;

  try {
    $("btn-pay").disabled = true;
    $("btn-pay").classList.add("btn-loading");
    $("btn-pay").textContent = "支付中...";

    const result = await api("POST", "/orders/" + window._current_order.order_id + "/pay", {
      chain_data: window._order_chain_data,
      gas_limit: window._current_order.gas_limit_adjusted,
      gas_multiplier: parseFloat($("create-gas-multiplier").value) || 1.2,
      payment_price: window._current_order.payment_price
    });

    show_alert("create-alert", "success", "上链成功！交易哈希: " + result.tx_hash);

    setTimeout(() => {
      window.location.hash = "#orders";
      load_orders();
    }, 5000);
  } catch (err) {
    show_alert("create-alert", "error", err.message);
    $("btn-pay").disabled = false;
    $("btn-pay").classList.remove("btn-loading");
    $("btn-pay").textContent = "确认支付";
  }
}

async function load_orders() {
  show_section("section-orders");
  try {
    const orders = await api("GET", "/orders");
    const tbody = $("orders-tbody");
    tbody.innerHTML = orders.map(o => `
      <tr>
        <td>${o.order_id}</td>
        <td>${esc(o.file_name)}</td>
        <td>${o.encryption_mode}</td>
        <td>${html_status(o.status)}</td>
        <td>${format_cny(o.paid_amount)}</td>
        <td>${o.final_cost != null ? format_cny(o.final_cost) : "-"}</td>
        <td>${o.refund_amount != null ? format_cny(o.refund_amount) : "-"}</td>
        <td>${o.gas_used || "-"}</td>
        <td>${o.gas_price ? (o.gas_price / 1e9).toFixed(2) + " Gwei" : "-"}</td>
        <td>${o.exchange_rate ? o.exchange_rate.toFixed(2) : "-"}</td>
        <td>${format_time(o.created_at)}</td>
        <td>${format_time(o.onchain_at)}</td>
        <td>${o.block_number || "-"}</td>
        <td>${o.tx_hash ? '<span class="mono" title="' + o.tx_hash + '">' + o.tx_hash.substring(0,10) + '...</span>' : "-"}</td>
        <td>${o.status === "success" ? '<a href="#" onclick="download_report(' + o.order_id + ')" style="color:var(--primary)">PDF</a>' : "-"}</td>
      </tr>
    `).join("") || '<tr><td colspan="15" style="text-align:center">暂无订单</td></tr>';
  } catch (err) {
    console.error(err);
  }
}

async function download_report(order_id) {
  try {
    const resp = await fetch(API_BASE + "/orders/" + order_id + "/report", {
      headers: auth_header()
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      alert(err.error || "下载失败");
      return;
    }
    const blob = await resp.blob();
    const disposition = resp.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
    const filename = match ? match[1].replace(/['"]/g, "") : "report.pdf";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error(err);
  }
}

window.onload = function () {
  if (token && currentUser && currentUser.user_name) {
    update_nav();
    show_section("section-dashboard");
    load_dashboard();
  } else {
    update_nav();
    show_section("section-login");
  }

  window.addEventListener("hashchange", function () {
    if (window.location.hash === "#orders") load_orders();
  });
};
