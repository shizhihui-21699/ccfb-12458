"""核心数据模型：扫描发现 (Finding) 与组件汇总 (Component)。"""
from __future__ import annotations

import dataclasses
import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class AssetType(str, enum.Enum):
    CODE = "code"              # 源码中的加密调用
    CONFIG = "config"          # TLS / SSH 套件配置
    CERT = "cert"              # 证书 / 密钥文件


class Severity(str, enum.Enum):
    CRITICAL = "critical"      # 已被攻破：MD5/SHA1 签名、ECB、DES、RSA1024 等
    HIGH = "high"              # 过渡风险：RSA/ECDH 经典非对称（Shor 可破）
    MEDIUM = "medium"          # 需关注：3DES、CBC 固定 IV、SHA1 非签名用途等
    INFO = "info"              # 合规现代算法或后量子算法


class Confidence(str, enum.Enum):
    HIGH = "high"      # 结构化识别（AST / 证书解析 / 套件解码）
    MEDIUM = "medium"  # 语言专属正则，带 API 上下文
    LOW = "low"        # 通用 token 兜底


@dataclass
class Finding:
    """单条密码资产发现。"""
    system: str                 # 所属系统（仓库目录名）
    asset_type: AssetType
    language: str               # python/java/go/js/c/cpp/config/x509/ssh-key/...
    file_path: str              # 相对扫描根的路径
    line: int                   # 行号；证书类为 0
    algorithm: str              # 规范化算法名，如 AES-128-ECB / RSA-2048 / SHA-256
    category: str               # hash/symmetric/asymmetric/kdf/rng/signature/kex/mac/tls-protocol
    variant_raw: str            # 代码/配置里的原始写法（用于"换个写法也认得出"举证）
    rule_id: str                # 命中的规则
    confidence: Confidence
    severity: Severity
    weak: bool                  # 是否弱用法（经典意义上的弱）
    pq_status: str              # broken-classical / pq-vulnerable / pq-adjust / pq-safe
    pq_note: str                # 后量子迁移说明
    context: str = ""           # 所在行/上下文片段
    key_usage: str = ""         # 证书：签名/加密用途
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        """去重身份：同一文件同一行同一算法只保留一条。"""
        h = hashlib.sha1()
        h.update("|".join([
            self.system, self.file_path, str(self.line),
            self.algorithm, self.category, self.asset_type.value,
        ]).encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["asset_type"] = self.asset_type.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["id"] = self.identity
        return d


@dataclass
class Component:
    """按算法聚合的"密码物料"（CBOM 组件）。"""
    algorithm: str
    category: str
    pq_status: str
    severity: Severity
    weak: bool
    count: int
    systems: set[str] = field(default_factory=set)
    examples: list[dict[str, str]] = field(default_factory=list)  # {system, file, raw}

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "category": self.category,
            "pq_status": self.pq_status,
            "severity": self.severity.value,
            "weak": self.weak,
            "count": self.count,
            "systems": sorted(self.systems),
            "examples": self.examples[:5],
        }
