"""后量子迁移准备度评估。

两个独立维度（监管视角要求同时回答"现在有没有弱用法"和"量子来了怎么办"）：
- classic_score 经典安全卫生：MD5/SHA1/ECB/RSA1024/弱协议/弱口令等
- pq_score      后量子准备度：Shor 风险面、Grover 调整面、是否已引入 PQC 与混合组

总分 0-100，分四档：
  >=85 ready / 70-84 progressing / 50-69 planning / <50 exposed
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import AssetType, Finding, Severity

# 每条发现的扣分（按严重度），同一系统内各维度封顶，避免单文件刷屏拉到负无穷
_PENALTY = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.INFO: 0,
}
_CLASSIC_CAP = 70          # 经典维度最多扣 70
_PQ_CAP = 60               # PQ 维度最多扣 60
_PQ_SAFE_BONUS_CAP = 15    # PQC/混合组的加分上限

# 迁移检查清单（NIST PQC 迁移路线 + 金融行业实践抽象）
CHECKLIST = [
    ("inventory", "建立密码物料清单（CBOM），资产可见", "所有加密调用、套件、证书均已盘点"),
    ("classical-weak", "清除经典弱算法（MD5/SHA1/ECB/3DES/RSA<2048/SSL-TLS1.1）", "无 critical 弱用法"),
    ("key-length", "对称密钥与哈希升级到 256 位安全等级（AES-256/SHA-384+）", "无 pq-adjust 项或已列入计划"),
    ("asym-inventory", "梳理全部非对称信任根与密钥交换（证书、SSH、JWT、mTLS、信封加密）", "pq-vulnerable 资产有清册与责任人"),
    ("pq-pilot", "在测试环境验证 ML-KEM/ML-DSA 及 TLS 混合组（X25519MLKEM768）", "代码/配置中出现 PQC 或混合组"),
    ("hybrid-tls", "对外 TLS 启用后量子混合密钥交换", "named groups / SSH KEX 含 mlkem"),
    ("cert-lifecycle", "缩短证书生命周期并建立自动化轮换，为 PQ 重签做准备", "无过期证书，有效期 ≤398 天"),
    ("key-management", "密钥进入 KMS/HSM 集中管理，消除弱口令私钥与硬编码密钥", "无 WEAK-KEY-PASSWORD 类发现"),
    ("crypto-agility", "架构支持算法可插拔（配置化套件、抽象加密层），无需大改即可切换 PQC", "架构评审项，扫描侧给证据提示"),
    ("supplier", "向第三方/供应商发出 PQ 迁移问卷并跟踪回执", "流程项，平台外跟踪"),
]


@dataclass
class SystemReadiness:
    system: str
    total_findings: int
    by_severity: dict[str, int]
    by_pq_status: dict[str, int]
    by_asset_type: dict[str, int]
    classic_score: int
    pq_score: int
    overall: int
    level: str
    level_cn: str
    checklist: list[dict]
    top_risks: list[dict] = field(default_factory=list)


def _level(score: int) -> tuple[str, str]:
    if score >= 85:
        return "ready", "可迁移（Ready）"
    if score >= 70:
        return "progressing", "推进中（Progressing）"
    if score >= 50:
        return "planning", "待规划（Planning）"
    return "exposed", "暴露（Exposed）"


def evaluate(system: str, findings: list[Finding]) -> SystemReadiness:
    by_sev = {s.value: 0 for s in Severity}
    by_pq = {"broken-classical": 0, "pq-vulnerable": 0, "pq-adjust": 0, "pq-safe": 0}
    by_type = {t.value: 0 for t in AssetType}
    classic_penalty = 0
    pq_penalty = 0
    pq_bonus = 0
    top: dict[str, dict] = {}

    for f in findings:
        by_sev[f.severity.value] += 1
        by_pq[f.pq_status] = by_pq.get(f.pq_status, 0) + 1
        by_type[f.asset_type.value] += 1
        pen = _PENALTY[f.severity]

        # 经典维度：broken-classical 与 medium 弱用法
        if f.pq_status == "broken-classical":
            classic_penalty += pen
        elif f.weak and f.severity == Severity.MEDIUM:
            classic_penalty += pen

        # PQ 维度：Shor 风险重罚，Grover 调整轻罚
        if f.pq_status == "pq-vulnerable":
            pq_penalty += min(pen, 6)
        elif f.pq_status == "pq-adjust":
            pq_penalty += 2
        if f.pq_status == "pq-safe" and f.category in ("asymmetric", "kex"):
            pq_bonus += 5  # 已出现 PQC/混合组

        # top risks 聚合
        key = f.algorithm
        entry = top.setdefault(key, {
            "algorithm": key, "severity": f.severity.value,
            "pq_status": f.pq_status, "count": 0, "sample": f.file_path,
            "weak": f.weak,
        })
        entry["count"] += 1

    classic_penalty = min(classic_penalty, _CLASSIC_CAP)
    pq_penalty = min(pq_penalty, _PQ_CAP)
    pq_bonus = min(pq_bonus, _PQ_SAFE_BONUS_CAP)

    classic_score = 100 - classic_penalty
    pq_score = max(0, min(100, 100 - pq_penalty + pq_bonus))
    overall = round(classic_score * 0.55 + pq_score * 0.45)
    level, level_cn = _level(overall)

    checklist = _build_checklist(findings, by_pq, by_sev)
    top_risks = sorted(top.values(), key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "info": 3}[x["severity"]], -x["count"]))[:8]

    return SystemReadiness(
        system=system, total_findings=len(findings),
        by_severity=by_sev, by_pq_status=by_pq, by_asset_type=by_type,
        classic_score=classic_score, pq_score=pq_score, overall=overall,
        level=level, level_cn=level_cn, checklist=checklist, top_risks=top_risks,
    )


def _build_checklist(findings: list[Finding], by_pq: dict, by_sev: dict) -> list[dict]:
    algos = {f.algorithm for f in findings}
    cats = {f.category for f in findings}
    files = {f.file_path for f in findings}
    has_pq = by_pq.get("pq-safe", 0) > 0 and any(
        f.pq_status == "pq-safe" and f.category in ("asymmetric", "kex") for f in findings)
    has_hybrid_tls = any(
        ("ML-KEM" in f.algorithm or "SNTRUP" in f.algorithm) and f.asset_type == AssetType.CONFIG
        for f in findings)
    has_expired = any(f.algorithm == "EXPIRED-CERT" for f in findings)
    has_long = any(f.algorithm == "LONG-LIVED-CERT" for f in findings)
    has_weak_pw = any(f.algorithm == "WEAK-KEY-PASSWORD" for f in findings)
    has_adjust = by_pq.get("pq-adjust", 0) > 0
    has_critical = by_sev.get("critical", 0) > 0
    has_vulnerable = by_pq.get("pq-vulnerable", 0) > 0
    # crypto-agility 的证据：套件/算法出现在配置文件而非硬编码
    config_algos = {f.algorithm for f in findings if f.asset_type == AssetType.CONFIG}

    states = {
        "inventory": ("done", "扫描已生成 CBOM"),
        "classical-weak": ("todo" if has_critical else "done",
                           "仍存在 critical 弱用法" if has_critical else "未发现经典弱算法"),
        "key-length": ("todo" if has_adjust else "done",
                       "存在需调整密钥长度/哈希等级的资产" if has_adjust else "对称与哈希等级满足 256 位基线"),
        "asym-inventory": ("inprogress" if has_vulnerable else "done",
                           f"{by_pq.get('pq-vulnerable', 0)} 项 Shor 风险资产已入册，待排期"
                           if has_vulnerable else "未发现经典非对称资产"),
        "pq-pilot": ("done" if has_pq else "todo",
                     "发现 ML-KEM/ML-DSA 或混合组使用" if has_pq else "未发现任何后量子算法试点"),
        "hybrid-tls": ("done" if has_hybrid_tls else "todo",
                       "TLS/SSH 已配置后量子混合组" if has_hybrid_tls else "未配置 PQ 混合密钥交换"),
        "cert-lifecycle": ("todo" if (has_expired or has_long) else "done",
                           "存在过期或超长生命周期证书" if (has_expired or has_long)
                           else "证书生命周期符合基线"),
        "key-management": ("todo" if has_weak_pw else "inprogress",
                           "发现弱口令保护的私钥/密钥库" if has_weak_pw
                           else "未发现弱口令；KMS/HSM 覆盖率需人工确认"),
        "crypto-agility": ("inprogress" if config_algos else "todo",
                           f"{len(config_algos)} 类算法已配置化" if config_algos
                           else "算法多为代码硬编码，建议抽象加密层"),
        "supplier": ("todo", "需在平台外发起供应商问卷"),
    }
    out = []
    for key, title, criterion in CHECKLIST:
        state, evidence = states[key]
        out.append({"key": key, "title": title, "criterion": criterion,
                    "state": state, "evidence": evidence})
    return out
