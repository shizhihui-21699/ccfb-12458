# 密码资产盘点与后量子迁移准备度平台

面向监管合规的**密码物料清单（CBOM, Cryptographic Bill of Materials）**平台：扫描源码仓库中的
加密调用、配置文件中的 TLS/SSH 套件、证书与密钥文件的算法和长度，自动标出
MD5、SHA1、RSA1024、ECB、3DES 等弱用法，并按系统给出**后量子（PQC）迁移准备度**评分。

## 它解决什么问题

监管要求列出系统里用到的所有密码算法、为后量子迁移做准备，但没人能说清代码和配置里到底用了什么。
本平台把三类散落的密码资产自动归集：

| 资产类型 | 扫描对象 | 识别方式 |
|---|---|---|
| `code` 源码加密调用 | Python / Java / Go / JS·TS / C·C++（另含 Ruby/PHP/C#/Rust 兜底） | Python AST 结构化 + 各语言专属正则 + 通用 token 兜底 |
| `config` 套件配置 | nginx / Apache / HAProxy / yaml / json / properties / ini / sshd_config | TLS 套件逐组件解码、SSH 套件映射、协议版本识别 |
| `cert` 证书密钥 | X.509 PEM/DER、PEM/OpenSSH 私钥、OpenSSH 公钥、PKCS#12 | `cryptography` 结构化解析签名算法、主体密钥算法与位长 |

**“同一处用法换个写法也认得出”**：所有原始写法经 `rules/catalog.py` 归一化到同一规范名。
例如下面 7 种 MD5 写法最终都归并为 `MD5`：

```python
hashlib.md5(x)                 # Python 直接调用
hashlib.new("md5")             # Python 间接构造
MessageDigest.getInstance("MD5")      # Java JCE
crypto.createHash("md5")       # Node.js
md5.New()                      # Go
hash('md5', ...) / md5(...)    # PHP
TLS_RSA_WITH_RC4_128_MD5       # TLS 套件里的 MD5 组件
```

## 快速开始

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) 生成演示用样例仓库与自造证书（离线，无需联网）
python -I scripts/gen_sample_certs.py
python -I scripts/gen_sample_repos.py

# 2) 命令行扫描 samples/ 下四个系统
python -m crypto_inventory.cli scan samples

# 3) 导出 CBOM（CycloneDX 1.5 crypto-components）或 CSV
python -m crypto_inventory.cli export samples --format cyclonedx -o cbom.json
python -m crypto_inventory.cli export samples --format csv -o findings.csv

# 4) 启动 Web 平台
python -m crypto_inventory.cli web samples --port 5000
# 打开 http://127.0.0.1:5000
```

## 四个样例系统（风险水平由高到低）

| 系统 | 特征 | 综合分（示例） | 等级 |
|---|---|---:|---|
| `legacy-payment-gateway` | MD5/SHA1/ECB/3DES/RC4、TLS1.0/1.1、SSH 弱套件、RSA1024、弱口令密钥库 | ~34 | 暴露 Exposed |
| `iot-firmware` | C/嵌入式 OpenSSL 弱算法、MD5 签名证书、过期证书、JWT none、导出级套件 | ~47 | 暴露 Exposed |
| `internal-portal` | PBKDF2/HMAC/AEAD 为主，残留 CBC/SHA1/RSA 经典非对称 | ~58 | 待规划 Planning |
| `data-pipeline` | AES-GCM/ChaCha20、TLS1.3、ML-KEM-768 试点与 X25519MLKEM768 混合组 | ~80 | 推进中 Progressing |

## 后量子状态四档（对齐 NIST PQC 迁移口径）

- **broken-classical**：经典意义上已被攻破/弃用（MD5、SHA1、ECB、DES、3DES、RSA<2048、SSL/TLS1.1…）
- **pq-vulnerable**：经典安全但 **Shor 算法可破**的非对称（RSA/DSA/ECDSA/Ed25519/X25519/DH/ECDH）
- **pq-adjust**：**Grover / 量子生日攻击**下强度减半，需调参数（AES-128、SHA-256 抗碰撞等 → 升级 256 位 / SHA-384+）
- **pq-safe**：量子安全裕度充足（AES-256、SHA-384+、ChaCha20-Poly1305、ML-KEM/ML-DSA 等 PQC）

准备度评分分两个独立维度：**经典安全卫生分**（55% 权重）与**后量子准备度分**（45%），
并输出 10 项迁移检查清单（CBOM 可见性、清弱算法、密钥长度、非对称信任根梳理、PQC 试点、
混合 TLS、证书生命周期、密钥管理、crypto-agility、供应商问卷）。

## 识别覆盖范围

- **Python（最高保真）**：AST 结构化识别 `hashlib` / `hmac` / `cryptography` /
  `pycryptodome` / `jwt` / `random`·`secrets` / `bcrypt`·`argon2`，含间接构造、关键字参数、变换串
- **Java/Kotlin、Go、JS/TS、C/C++**：语言专属 API 正则（MessageDigest/Cipher、crypto/md5、
  createHash、EVP_* 等），解析 `AES/CBC/PKCS5Padding` 一类变换串
- **Ruby/PHP/C#/Rust**：专属规则 + 通用 token 兜底
- **配置**：IANA 与 OpenSSL 两种 TLS 套件命名、TLS1.3 套件、SSH KEX/Cipher/MAC/HostKey、
  YAML 块列表与行内数组、协议版本、PQ 混合组（mlkem/sntrup）
- **证书密钥**：签名 OID 拆分（非对称 + 哈希）、RSA/DSA/EC 位长与曲线、过期/超长生命周期、
  弱口令 PEM 与 PKCS#12、损坏文件容错

每条发现带 `confidence`（high/medium/low），同一行同一算法保留置信度最高者；
注释内容会被剥离，不产生误报。

## 目录结构

```
crypto_inventory/
  models.py            # Finding / Component 数据模型与枚举
  rules/catalog.py     # 算法知识库：归一化、弱用法判定、PQ 四档分类
  scanners/
    code_scanner.py    # 源码扫描（Python AST + 多语言正则 + token 兜底）
    config_scanner.py  # TLS/SSH 套件解码与配置识别
    cert_scanner.py    # X.509 / 私钥 / OpenSSH / PKCS#12 解析
  readiness.py         # 准备度评分与 10 项检查清单
  inventory.py         # 编排与 CBOM 组件聚合
  exporter.py          # CycloneDX 1.5 / CSV 导出
  store.py             # SQLite 扫描快照持久化
  web.py + templates/  # Flask Web 平台（仪表盘/详情/检索/CBOM）
  cli.py               # scan / export / web 命令
samples/               # 四个自造样例系统（生成物）
scripts/               # 样例仓库与证书生成器
tests/                 # 58 个 pytest 用例
```

## 测试

```bash
python -I -m pytest tests/ -q
```

覆盖：归一化与分级、多语言多写法识别、注释剥离、去重与置信度择优、TLS/SSH 套件解码、
证书/密钥/PKCS#12 解析、CBOM 导出、SQLite 持久化、Flask 全端点与路径穿越防护。

## 局限与后续

- 静态分析不运行代码：动态拼接的算法名、反射加载、配置中心下发的套件需要结合运行时/网络探测
- 通用 token 兜底可能产生低置信度条目，已在 UI 标注并让结构化识别优先
- PQC 库生态仍在演进，FIPS 203/204/205 的命名按 NIST 标准（ML-KEM/ML-DSA）归一
- 供应商问卷、crypto-agility 架构评审属流程项，平台给出证据提示但需人工闭环
