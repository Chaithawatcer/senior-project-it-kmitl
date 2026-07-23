"""
central_schema.py — Central Schema (ARCHITECTURE.md ขั้นที่ 2: Normalization)

โครงสร้างข้อมูลกลางที่ทั้ง Pipeline 1 (เชิงรับ) และ Pipeline 2 (เชิงรุก) แปลง input
มาอยู่ในรูปเดียวกันก่อนเข้าสู่ชั้นถัดไป — ตอนนี้ implement เฉพาะฝั่งเชิงรับ (SIEM alert)
ฝั่งเชิงรุก (CTI feed) ยังไม่ implement — `pipeline` field เผื่อไว้แล้วสำหรับตอนทำ

ครอบคลุมแค่ขั้นที่ 1-3 ของ Pipeline 1 ตาม ARCHITECTURE.md:
  [1] รับ mock SIEM alert (Webhook)      — อยู่ที่ api.py POST /alerts/ingest
  [2] Normalize → Central Schema, t0-t1, dedup — อยู่ในไฟล์นี้ (normalize_alert + compute_dedup_key)
  [3] สกัด observables (IP, hash, account, host) — อยู่ในไฟล์นี้ (extract_observables)

ขั้นที่ 4 เป็นต้นไป (CTI enrichment, NCSC/Escalation, RAG playbook, Notification/Review Gate)
ยังไม่ implement ในรอบนี้โดยตั้งใจ — timestamps t2-t6 เผื่อ field ไว้ให้แล้วแต่จะเป็น null จนกว่าจะทำ
"""

import hashlib
import re
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- schema


class SourceInfo(BaseModel):
    type: str  # "siem_alert" | "cti_feed" (เชิงรุกยังไม่ implement)
    ref: str | None = None  # เช่น Wazuh rule id
    raw: dict  # payload ดิบ เก็บไว้ตรวจสอบย้อนกลับ (ตาม ARCHITECTURE.md §3 "raw payload เก็บเสมอ")


class Timestamps(BaseModel):
    t0_ingested: str | None = None
    t1_normalized: str | None = None
    t2_enriched: str | None = None  # CTI enrichment — ยังไม่ implement (ขั้น 4)
    t3_assessed: str | None = None  # NCSC/Escalation — ยังไม่ implement (ขั้น 5-6)
    t4_playbook_done: str | None = None  # RAG generation — ยังไม่ implement (ขั้น 7)
    t5_notified: str | None = None  # Notification — ยังไม่ implement (ขั้น 8)
    t6_human_approved: str | None = None  # Review Gate — ยังไม่ implement (ขั้น 8)


class Entities(BaseModel):
    ips: list[str] = []
    hashes: list[str] = []
    domains: list[str] = []
    accounts: list[str] = []
    hosts: list[str] = []


class CaseRecord(BaseModel):
    case_id: str
    pipeline: str = "reactive"
    dedup_key: str
    source: SourceInfo
    timestamps: Timestamps
    entities: Entities
    mitre_techniques: list[str] = []
    threat_name: str = "Unknown Threat"
    raw_severity: str | None = None  # severity ดิบจาก SIEM (ยังไม่ใช่ NCSC — รอขั้น 5)
    severity: str = "medium"  # bucketed จาก raw_severity (critical/high/medium/low) — ใช้แสดงใน Alert Context
    # ⭐ ฟิลด์ด้านล่างคือ input ตรงของ POST /assess/severity (ขั้น 5-6) — คำนวณตั้งแต่ขั้น normalize
    # เพื่อให้ workflow ที่เหลือ (Assess Severity ➜ RAG ➜ Assemble) เรียกต่อจาก CaseRecord ได้เลย
    # ไม่ต้องมี normalize logic ซ้ำสองที่ (ยุบรวมจาก n8n's เดิม Normalize Alert Code node)
    account_privilege: str = "standard"  # "domain_admin" | "privileged" | "standard" | "unknown"
    attack_success: bool = False  # TODO: ยังไม่มี correlation ข้าม alert หา event 4624 — default False เสมอ
    distinct_accounts: int = 1
    # ⚠️ TODO: CTI enrichment (VirusTotal/AbuseIPDB) ยังไม่ implement — ดู HANDOFF.md งานที่เหลือ
    cti_verdict: str = "unknown"  # "malicious" | "suspicious" | "clean" | "unknown"
    alert: dict = {}  # alert ที่ normalize แล้ว (host/source_ip/target_user/ฯลฯ) — ใช้แสดง Alert Context


class AlertIngestRequest(BaseModel):
    """
    รับ raw SIEM alert ทั้งก้อน — ไม่บังคับ schema เป๊ะเพราะ SIEM ต่างยี่ห้อ field ต่างกัน
    (extra="allow" กันพัง ถ้า field เกินจากที่ระบุไว้ตรงๆ)
    รูปแบบที่ทดสอบแล้วคือ Wazuh Windows Event style (data.win.eventdata.*) ตรงกับ n8n mock
    """

    model_config = ConfigDict(extra="allow")
    timestamp: str | None = None
    rule: dict = {}
    agent: dict = {}
    data: dict = {}
    full_log: str | None = None
    location: str | None = None


# ---------------------------------------------------------------- ค่าประกอบ Assess Severity (ย้ายมาจาก n8n Code node เดิม)

# ⚠️ Stand-in สำหรับ AD group membership lookup จริง (ยังไม่ได้ต่อ AD)
# ตอนขึ้นจริงควรถาม AD ว่าบัญชีนี้อยู่กลุ่ม Domain Admins/Privileged หรือไม่ ไม่ใช่ hardcode ตาราง
# ย้ายมาจาก n8n "Normalize Alert" Code node เดิม — รวม logic ไว้ที่เดียวตาม HANDOFF.md §7
ACCOUNT_PRIVILEGE_LOOKUP = {
    "admin_somchai": "domain_admin",
}


def severity_map(level: int) -> str:
    """bucketed severity จาก Wazuh rule.level ดิบ — ใช้แสดงผลเท่านั้น ไม่ใช่ NCSC (รอขั้น 5-6)"""
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    return "low"


# ---------------------------------------------------------------- ขั้นที่ 2: dedup


def compute_dedup_key(technique_ids: list[str], primary_entity: str) -> str:
    """
    dedup_key = hash(technique ชุดที่เรียงแล้ว + entity หลักของ alert)
    ตาม ARCHITECTURE.md §3: "dedup_key: hash(source_id + entity หลัก)"

    ใช้ entity หลัก (เช่น target account) แทน source_id ของ SIEM ตรงๆ เพราะ Wazuh บางกรณี
    ยิง event id ไม่ซ้ำกันทุกครั้งแม้จะเป็นเหตุการณ์ต่อเนื่องเดียวกัน (เช่น brute force ชุดเดียว
    ที่ถูกแตกเป็นหลาย alert) — การ hash จาก technique+entity ทำให้ alert ที่เป็นแคมเปญเดียวกัน
    ได้ dedup_key เดียวกัน ไม่ต้องพึ่ง ID ของ SIEM ที่แต่ละยี่ห้อออกแบบมาไม่เหมือนกัน
    """
    norm_entity = re.sub(r"\W+", "_", primary_entity.lower()) if primary_entity else "unknown"
    tech_part = "_".join(sorted(technique_ids)) if technique_ids else "notech"
    raw = f"{tech_part}::{norm_entity}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- ขั้นที่ 2: normalize


def normalize_alert(raw: dict) -> dict:
    """
    Anti-Corruption Layer — แปลง schema เฉพาะของ SIEM ยี่ห้อหนึ่ง (ตอนนี้รองรับ Wazuh
    Windows Event style) ให้เป็นชื่อ field กลางที่ชั้นถัดไปใช้ร่วมกัน โดยไม่ต้องรู้ว่า
    ข้างล่างเป็น SIEM ยี่ห้อไหน — วันที่เปลี่ยนจาก Wazuh ไปยี่ห้ออื่น แก้แค่ฟังก์ชันนี้จุดเดียว
    """
    ev = (raw.get("data") or {}).get("win", {}).get("eventdata", {}) or {}
    ctx = (raw.get("data") or {}).get("additional_context", {}) or {}
    win_system = (raw.get("data") or {}).get("win", {}).get("system", {}) or {}

    return {
        "host": (raw.get("agent") or {}).get("name"),
        "source_ip": ev.get("ipAddress") or (raw.get("data") or {}).get("srcip"),
        "target_user": ev.get("targetUserName") or (raw.get("data") or {}).get("srcuser"),
        "target_domain": ev.get("targetDomainName"),
        "logon_type": ev.get("logonType"),
        "sub_status": ev.get("subStatus"),
        "status_code": ev.get("status"),
        "workstation_name": ev.get("workstationName"),
        "event_id": win_system.get("eventID"),
        "full_log": raw.get("full_log", "") or "",
        "failed_attempts": ctx.get("failed_attempts"),
        "distinct_accounts": ctx.get("distinct_accounts", 1),
        "windows_event_ids": ctx.get("windows_event_ids", []),
        # เก็บไว้เพื่อ backward-compat กับ Alert Context / prompt เดิม (เทียบเท่า job.alert ของ n8n เดิม)
        "rule_id": (raw.get("rule") or {}).get("id"),
        "rule_description": (raw.get("rule") or {}).get("description"),
        "log_source": raw.get("location"),
        "timestamp": raw.get("timestamp"),
    }


# ---------------------------------------------------------------- ขั้นที่ 3: extract observables

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")


def extract_observables(normalized: dict) -> Entities:
    """
    สกัด observables จาก alert ที่ normalize แล้ว (เรียกหลัง normalize_alert เท่านั้น)
    อ่านจาก field ที่ structured ก่อน (แม่นกว่า) แล้วเสริมด้วย regex จาก full_log
    เผื่อมี IP/hash อื่นที่ไม่ได้อยู่ใน field หลัก (เช่น IP ปลายทางที่ปรากฏใน log message)
    """
    ips: set[str] = set()
    hosts: set[str] = set()
    accounts: set[str] = set()
    hashes: set[str] = set()

    if normalized.get("source_ip"):
        ips.add(normalized["source_ip"])
    if normalized.get("host"):
        hosts.add(normalized["host"])
    if normalized.get("target_user"):
        accounts.add(normalized["target_user"])

    full_log = normalized.get("full_log", "") or ""
    ips.update(_IP_RE.findall(full_log))
    hashes.update(_HASH_RE.findall(full_log))

    return Entities(
        ips=sorted(ips),
        hashes=sorted(hashes),
        domains=[],
        accounts=sorted(accounts),
        hosts=sorted(hosts),
    )


# ---------------------------------------------------------------- ประกอบทั้ง 3 ขั้น


def build_case_record(raw: dict) -> CaseRecord:
    """ประกอบขั้นที่ 2 (normalize) + 3 (extract observables) เป็น CaseRecord เดียว — ยังไม่ทำ dedup lookup ที่นี่ (ให้ผู้เรียกเช็คก่อนด้วย dedup_key)"""
    t0 = now_iso()
    normalized = normalize_alert(raw)
    t1 = now_iso()

    technique_ids = (raw.get("rule") or {}).get("mitre", {}).get("id", []) or []
    threat_name = (
        ((raw.get("rule") or {}).get("mitre", {}).get("technique") or [None])[0]
        or (raw.get("rule") or {}).get("description")
        or "Unknown Threat"
    )

    primary_entity = normalized.get("target_user") or normalized.get("source_ip") or "unknown"
    dedup_key = compute_dedup_key(technique_ids, primary_entity)

    entities = extract_observables(normalized)

    level = (raw.get("rule") or {}).get("level", 0)
    account_privilege = ACCOUNT_PRIVILEGE_LOOKUP.get(normalized.get("target_user"), "standard")

    return CaseRecord(
        case_id=f"case_{uuid.uuid4().hex[:12]}",
        pipeline="reactive",
        dedup_key=dedup_key,
        source=SourceInfo(
            type="siem_alert",
            ref=(raw.get("rule") or {}).get("id"),
            raw=raw,
        ),
        timestamps=Timestamps(t0_ingested=t0, t1_normalized=t1),
        entities=entities,
        mitre_techniques=technique_ids,
        threat_name=threat_name,
        raw_severity=str(level),
        severity=severity_map(level),
        account_privilege=account_privilege,
        attack_success=False,
        distinct_accounts=normalized.get("distinct_accounts", 1),
        cti_verdict="unknown",
        alert=normalized,
    )
