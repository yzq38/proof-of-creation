<div align="center">

# Proof Of Creation

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pixi](https://img.shields.io/badge/Env-pixi-6D28D9)](https://pixi.prefix.dev/)
[![Flask](https://img.shields.io/badge/Web-Flask-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Solidity](https://img.shields.io/badge/Contract-Solidity-363636?logo=solidity&logoColor=white)](https://soliditylang.org/)
[![Tkinter](https://img.shields.io/badge/GUI-tkinter-1F2937)](https://docs.python.org/3/library/tkinter.html)
[![Web3.py](https://img.shields.io/badge/Chain-Web3.py-F16822?logo=ethereum&logoColor=white)](https://web3py.readthedocs.io/)
[![cryptography](https://img.shields.io/badge/Crypto-cryptography%20%2B%20pqcrypto-6366F1)](https://cryptography.io/)
[![Release](https://img.shields.io/github/v/release/czt0221/proof-of-creation)](https://github.com/czt0221/proof-of-creation/releases/latest)

[![Download](https://img.shields.io/badge/Download-Latest%20Release-2ea44f?style=for-the-badge)](https://github.com/czt0221e/proof-of-creation/releases/latest)

</div>

**Proof Of Creation（PoC）** 是一个基于区块链的数字作品存证平台。用户对文件计算 SHA3-256 摘要并 Ed25519 签名，将哈希与签名写入以太坊 Sepolia 测试网，形成不可篡改的版权证明。服务器不存储用户公钥及上链数据，报告生成时从链上回读。配套开源桌面加密工具支持 Ed25519 / RSA-2048 / ML-DSA / SLH-DSA 等算法，所有密钥采用 PKCS#8 / SPKI 标准 DER 格式。

## 功能概览

- **用户系统** — 注册/登录（JWT + token 覆盖），储值余额，提现
- **普通存证** — 浏览器端 SHA3-256 + Ed25519 签名，128B 定长上链
- **进阶存证** — 支持自定义算法，变长 `bytes` 上链，适配后量子签名
- **订单管理** — 历史记录、费用明细（final_cost / refund_amount）
- **PDF 存证报告** — 从链上回读数据，生成含 hex + base64 双编码的报告
- **混合支付** — 余额优先扣款 + 模拟在线支付，多退少不补
- **桌面加密工具** — 6 个功能页：哈希 / 密钥生成 / 生成公钥 / 签名 / 验签 / 验证公私钥对
- **后量子支持** — ML-DSA (Dilithium2/3/5) 与 SLH-DSA (SPHINCS+-128s)，含 NIST 草案 OID 包装

## 技术栈

- `Python 3.14` — 服务端 + 桌面工具
- `Flask` — Web API 服务
- `Web3.py` — 以太坊交互（Sepolia）
- `ReportLab` — PDF 报告生成
- `Solidity 0.8.19` — 智能合约（BasicRecord + AdvancedRecord）
- `cryptography` — Ed25519 / RSA 密钥操作
- `pqcrypto` (CFFI) — Dilithium2/3/5、SPHINCS+-128s 后量子签名
- `vanilla JS` — 前端 SPA，零框架
- `@std/crypto` (ESM) — 浏览器端 SHA3-256
- `Web Crypto API` — 浏览器端 Ed25519 签名
- `tkinter` — 桌面工具 GUI
- `pixi` — 环境与依赖管理
- `PyInstaller` — 桌面工具打包

## 快速启动

### 环境要求

- `Windows`
- 已安装 [`pixi`](https://pixi.prefix.dev/)
- 已安装 [`Chrome`](https://www.google.cn/chrome/) 或基于 `Chromium` 内核的主流现代浏览器的最新稳定版本
- 已接入 **Internet**
- 配置文件 `.env`（基于 `.env.example` 填写）

### 安装依赖

```bash
pixi install               # 默认环境 (Flask 服务端)
pixi install -e poc-crypto # poc-crypto 环境 (桌面加密工具)
pixi install -e build      # build 环境 (PyInstaller 打包)
```

### 运行方式

```bash
# 启动 Web 服务端
pixi run server

# 启动桌面加密工具
pixi run -e poc-crypto crypto
```

启动前需将 `.env.example` 复制为 `.env` 并填写实际参数（私钥、合约地址、JWT 密钥等），SSL 证书（可选，未配置证书时自动降级为 HTTP）放入 `ssl/` 目录。

### 打包桌面工具

```bash
pixi run -e build build-crypto
# 输出: dist/poc-crypto.exe
```

## 项目结构

### 仓库文件

```text
proof-of-creation/
├── .gitignore                  # Git 忽略规则
├── pixi.toml                   # pixi 环境、依赖和任务定义
├── pixi.lock                   # pixi 锁文件
├── README.md                   # 项目说明
├── ssl/                        # HTTPS 证书（cert.pem + key.pem，可选，未配置证书时自动降级为 HTTP）
├── .env                        # 环境变量（基于 .env.example，自行准备）
├── .env.example                # 环境变量模板（含完整注释）
│
├── server/                     # Flask 服务端
│   ├── app.py                  # 入口，SSL，后台订单过期线程
│   ├── deploy.py               # 合约编译与部署脚本
│   ├── routes/
│   │   ├── auth.py             # 注册/登录/登出，JWT + jti（token 覆盖）
│   │   ├── orders.py           # 创建/支付/列表/详情/PDF 报告
│   │   └── user.py             # 余额查询/储值/提现
│   ├── services/
│   │   ├── blockchain.py       # Web3 连接，Gas 估算，交易发送
│   │   ├── payment.py          # 定价、实际成本、退款计算
│   │   ├── pricing.py          # ETH/CNY 汇率（30s 缓存 + 兜底值）
│   │   └── report.py           # PDF 存证报告（ReportLab，hex + base64 双编码）
│   └── utils/
│       ├── config.py           # .env 配置加载与完整性校验
│       ├── db.py               # SQLite 管理（WAL 模式，外键约束）
│       └── logger.py           # 控制台 + 按日期滚动文件日志
│
├── contracts/                  # Solidity 智能合约
│   ├── BasicRecord.sol         # bytes32 定长存证（Ed25519 128B 模式）
│   └── AdvancedRecord.sol      # bytes 变长存证（进阶/PQ 模式）
│
├── web/                        # 前端 SPA（vanilla JS，零框架）
│   ├── templates/
│   │   └── index.html          # 单页，登录/注册/控制台/创建/历史
│   └── static/
│       ├── css/style.css       # 样式
│       └── js/
│           ├── crypto.js       # @std/crypto SHA3-256 + Web Crypto API Ed25519
│           └── app.js          # 业务逻辑，API 调用，JWT 管理
│
├── poc-crypto/                 # 桌面加密工具（tkinter）
│   └── main.py                 # 6 功能页，ASN.1 DER 编解码，PKCS 标准
│
├── data/                       # SQLite 数据库 (poc.db)（运行后生成的文件）
├── logs/                       # 服务端日志（运行后生成的文件）
├── dist/                       # PyInstaller 打包输出（运行后生成的文件）
└── build/                      # PyInstaller 构建缓存（运行后生成的文件）
```

## 智能合约

合约已部署于 Sepolia 测试网，地址公开，可在 [Sepolia Etherscan](https://sepolia.etherscan.io/) 查看。

| 合约 | 地址 | 说明 |
|---|---|---|
| BasicRecord | `0xA2BC43AA22D46Bb56934a2671871eA0d16E99AC3` | `bytes32` × 4：hash / sig1 / sig2 / userid |
| AdvancedRecord | `0xc495633D2a960AC7fF5dd9318D747e9Bb7D67f23` | `bytes` × 2 + `bytes32`：hash / sig / userid |

## 桌面加密工具

| 页面 | 功能 | 算法 |
|---|---|---|
| 哈希计算 | 文件/数据摘要 | SHA-256/512、SHA3-256/512、BLAKE2b-256、BLAKE2s-256 |
| 密钥生成 | 生成新密钥对 | Ed25519 / RSA-2048 / Dilithium2/3/5 / SPHINCS+-128s |
| 生成公钥 | 从 PKCS#8 私钥恢复 SPKI 公钥 | Ed25519（仅此支持） |
| 签名 | OID 自动识别 + RSA 哈希选择 | 全算法 |
| 验签 | OID 自动识别 + RSA 哈希选择 | 全算法 |
| 验证公私钥对 | 交叉验证公私钥匹配 | 全算法 |

- 所有密钥统一 PKCS#8（私钥）/ SPKI（公钥）标准 DER 格式
- 输出支持 DER + PEM 双格式导出
- 后量子算法使用 NIST 草案 OID（FIPS 204/205），手写 ASN.1 DER 包装
- Hex / Base64 输入格式页级切换

## 存证流程

### 定价公式

```
预估Gas费 = Gas单价 × Gas上限(预估用量×120%) × ETH/CNY汇率
支付价格  = 预估Gas费 × 150% + 0.20(固定手续费)
实际费用  = 实际Gas费 × 1.05(比例手续费) + 0.20
退款      = 支付价格 - 实际费用  (多退少不补)
```

### 订单生命周期

```
创建 → [60秒内支付] → 二次校验 → 上链 → 结算退款
                  ↘ 超时 → 取消
      二次校验失败 → 退款(全额)
            上链失败 → 退款(全额)
```

### 存证链路

```
文件 → SHA3-256 → 32B 摘要 → Ed25519.sign → 64B 签名
                                   │
                          SHA3-256(pubkey) → 32B UserID
                                   │
         链上存储: hash(32B) + sig(64B) + userid(32B) = 128B
```

## 配置参考

基于 `.env.example`：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `NODE_URL` | 公共 Sepolia RPC | 以太坊节点 |
| `CHAIN_ID` | 11155111 | Sepolia 测试网 |
| `ORDER_EXPIRY` | 60 | 订单有效期（秒） |
| `FIXED_FEE` | 0.20 | 固定手续费（CNY） |
| `FEE_RATE` | 0.05 | 比例手续费 |
| `MIN_GAS_MULTIPLIER` | 1.2 | Gas 上限最小倍率 |
| `EXCHANGE_RATE_API` | `cny.rate.sx` | ETH/CNY 汇率（Sepolia 测试币无真实经济价值，以主网 ETH 价值为参考） |
| `JWT_EXPIRY` | 86400 | Token 有效期（秒） |
| `SSL_CERT` / `SSL_KEY` | `ssl/` | HTTPS 证书路径 |

## ⚠️ 环境要求与合规声明

本系统原型**仅用于教学与技术验证目的**，可能存在严重的安全漏洞，以及涉及中国大陆境内相关法律法规，**禁止接入任何公有区块链主网**（Sepolia等测试币，仅限教学与技术验证用途，无真实经济价值），也**禁止用于真实交易或营利性业务**。

### 浏览器与网络环境说明

- 本系统的前端加密功能依赖 **Web Crypto API**。该 API 在 HTTP 环境下仅在 `127.0.0.1` / `localhost` 等本地回环地址中可用；若需要通过非本地地址访问，必须配置 **HTTPS** 证书。
- 为方便局域网内演示与测试，可将个人域名解析至运行服务器的局域网 IP 地址，并申请有效证书启用 HTTPS。若不导入证书，系统将自动降级为 HTTP。

### 中国境内合规注意事项

根据中国大陆相关法律法规：
- 对公网提供 Web 服务需要完成 **工信部 ICP 备案**。个人 IP 地址无法备案，因此**本系统不得部署于公网环境**，仅建议在**隔离的局域网**中进行教学或开发测试。
- 根据[《关于进一步防范和处置虚拟货币等相关风险的通知》（银发〔2026〕42 号）](https://www.csrc.gov.cn/csrc/c100028/c7614318/content.shtml)，加密货币（如比特币、以太坊、USDT）**不具有与法定货币等同的法律地位**，不能作为货币在市场上流通。任何组织或个人**严格禁止**以经营为目的从事加密数字货币相关业务活动。
- 本系统原型涉及“人民币与加密数字货币兑换”的业务流程模拟，此类设计**仅作为技术教学示意**，不得在实际环境中以营利方式运行或对外提供服务。
- **严禁在中国大陆境内**以任何形式修改、完善本项目并部署于公用网络中。

请所有使用者自觉遵守当地法律法规，仅将本项目用于合法的学习与研究目的。