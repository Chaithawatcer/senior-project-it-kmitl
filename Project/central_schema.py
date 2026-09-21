"""
central_schema.py — Central Schema (ARCHITECTURE.md ขั้นที่ 2: Normalization)

โครงสร้างข้อมูลกลางที่ทั้ง Pipeline 1 (เชิงรับ) และ Pipeline 2 (เชิงรุก) แปลง input
มาอยู่ในรูปเดียวกันก่อนเข้าสู่ชั้นถัดไป

ฝั่งเชิงรับ (Pipeline 1 ขั้น 1-3):
  [1] รับ mock SIEM alert (Webhook)      — อยู่ที่ api.py POST /alerts/ingest
  [2] Normalize → Central Schema, t0-t1, dedup — normalize_alert + compute_dedup_key
  [3] สกัด observables (IP, hash, account, host) — extract_observables

ฝั่งเชิงรุก (Pipeline 2 ขั้น 1-3):
  [1] ดึงข่าวตามรอบเวลา (mock feed ก่อน)  — อยู่ที่ api.py POST /intel/ingest
  [2] Normalize → IntelRecord, t0-t1, dedup ข้ามแหล่งข่าว — build_intel_record + compute_intel_dedup_key
  [3] สกัด facts + IoCs แบบ verbatim     — extract_intel_iocs + extract_intel_facts

⚠️ ขั้นที่ 3 ฝั่งรุก ARCHITECTURE.md เขียนว่าเป็น "LLM node (extraction prompt)" — รอบ mock นี้
ใช้ regex + sentence matching แบบ deterministic แทน (facts ทุกประโยคเป็น substring ตรงจาก
ต้นฉบับ = verbatim โดยโครงสร้าง ไม่มีทาง hallucinate) — เหตุผลเดียวกับ NCSC ใน HANDOFF.md §4.6
ตอนต่อข่าวจริงที่โครงสร้างหลากหลายค่อยตัดสินใจว่าจะยกระดับเป็น LLM extraction ไหม
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


# ---------------------------------------------------------------- Pipeline 2 (เชิงรุก) schema


class IntelIngestRequest(BaseModel):
    """
    รับข่าว/advisory 1 ชิ้นจาก CTI feed (ตอนนี้ mock — ของจริงคือ RSS item จาก CISA/The Hacker News)
    extra="allow" เหตุผลเดียวกับ AlertIngestRequest: แต่ละ feed มี field ไม่เหมือนกัน
    """

    model_config = ConfigDict(extra="allow")
    source: str = "unknown_feed"  # ชื่อ feed เช่น "CISA", "The Hacker News"
    title: str = ""
    link: str | None = None
    published: str | None = None  # เวลาที่ข่าวเผยแพร่ (t0 ฝั่งรุก = เวลารับเข้า ไม่ใช่เวลาข่าวออก)
    content: str = ""  # เนื้อหาเต็ม (ของจริงต้องดึงจาก link ก่อน — mock ส่งมาพร้อมเลย)


class IntelIocs(BaseModel):
    """IoCs ที่สกัดได้จากเนื้อข่าว — เก็บแบบ refang แล้ว (ตอนแสดงผลค่อย defang กลับ)"""

    ips: list[str] = []
    hashes: list[str] = []
    domains: list[str] = []
    cves: list[str] = []


class IntelRecord(BaseModel):
    intel_id: str
    pipeline: str = "proactive"
    dedup_key: str
    source: SourceInfo  # type="cti_feed", ref=link
    timestamps: Timestamps  # ใช้ t0_ingested/t1_normalized ร่วมกับฝั่งเชิงรับ
    feed_name: str
    title: str
    link: str | None = None
    published: str | None = None
    threat_name: str  # = title (ใช้เป็นชื่อ playbook + ส่วนหนึ่งของ query ตอน retrieve)
    mitre_techniques: list[str] = []  # สกัดจาก T-code ที่ปรากฏในเนื้อข่าวตรง ๆ (mock phase)
    iocs: IntelIocs = IntelIocs()
    facts: list[str] = []  # ประโยค verbatim จากต้นฉบับที่มี IoC/CVE/technique — บริบทชั้น (ก) ของ RAG
    content_excerpt: str = ""  # เนื้อหาย่อไว้ดูใน record (raw เต็มอยู่ใน source.raw แล้ว)


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


# ================================================================ Pipeline 2 (เชิงรุก) ขั้นที่ 2-3


def refang(text: str) -> str:
    """
    แปลง IoC ที่ถูก defang ในข่าว (185.220.101[.]45, hxxp://evil[.]top) กลับเป็นรูปปกติ
    ก่อนเข้า regex — ข่าว CTI จริงแทบทุกสำนัก defang IoC เสมอเพื่อกันคนเผลอคลิก
    """
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def defang(ioc: str) -> str:
    """defang จุดสุดท้ายก่อนแสดงผลในเอกสาร/ข้อความแจ้งเตือน — กันคนอ่านเผลอคลิก IoC จริง"""
    if "." not in ioc:
        return ioc
    head, _, tail = ioc.rpartition(".")
    return f"{head}[.]{tail}"


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# จำกัด TLD ที่พบบ่อยในข่าว CTI — กัน false positive จากชื่อไฟล์/ประโยคทั่วไป (mock phase ยอมรับได้)
_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.(?:com|net|org|io|ru|cn|xyz|info|top|onion|site|club)\b",
    re.IGNORECASE,
)
# ตัด domain ของสำนักข่าว/องค์กรที่อ้างอิงบ่อย ไม่ใช่ IoC
_DOMAIN_ALLOWLIST = {
    "thehackernews.com", "cisa.gov", "bleepingcomputer.com", "microsoft.com",
    "mitre.org", "attack.mitre.org", "nist.gov", "ncsc.gov.uk",
}


def extract_intel_iocs(content: str) -> tuple[IntelIocs, list[str]]:
    """
    [3] สกัด IoCs + MITRE technique จากเนื้อข่าว (refang ก่อนแล้วค่อย regex)
    คืน (iocs, technique_ids) — technique แยกออกมาเพราะไม่ใช่ IoC แต่เป็น mapping สำหรับ RAG

    ⚠️ mock phase: technique เอาเฉพาะ T-code ที่ปรากฏในข่าวตรง ๆ (CISA advisory มีตาราง
    ATT&CK ให้เสมอ) — การ map จากคำบรรยายพฤติกรรม → technique (ขั้นที่ 4 ของ ARCHITECTURE.md
    ที่เป็น LLM node) ยังไม่ทำในรอบนี้
    """
    text = refang(content)

    ips = sorted(set(_IP_RE.findall(text)))
    hashes = sorted(set(_HASH_RE.findall(text)))
    cves = sorted({c.upper() for c in _CVE_RE.findall(text)})
    techniques = sorted(set(_TECHNIQUE_RE.findall(text)))

    domains = set()
    for d in _DOMAIN_RE.findall(text):
        d_lower = d.lower()
        if d_lower in _DOMAIN_ALLOWLIST or any(d_lower.endswith("." + a) for a in _DOMAIN_ALLOWLIST):
            continue
        domains.add(d_lower)

    return IntelIocs(ips=ips, hashes=hashes, domains=sorted(domains), cves=cves), techniques


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def extract_intel_facts(content: str, iocs: IntelIocs, techniques: list[str], max_facts: int = 8) -> list[str]:
    """
    [3] สกัด "ข้อเท็จจริง" = ประโยคต้นฉบับ (verbatim, ยัง defang อยู่ตามที่ข่าวเขียน)
    ที่มี IoC / CVE / technique อย่างน้อย 1 ตัว — เป็นบริบทชั้น (ก) ตอนสร้าง proactive playbook

    verbatim โดยโครงสร้าง: ทุก fact เป็น substring ตรงจาก content ไม่มีการ paraphrase
    (ตรงเจตนา ARCHITECTURE.md §3 ขั้นที่ 3 "คัดข้อความตรงจากต้นฉบับเท่านั้น" โดยไม่ต้องพึ่ง LLM)
    """
    markers = set(iocs.ips) | set(iocs.hashes) | set(iocs.domains) | set(iocs.cves) | set(techniques)
    if not markers:
        return []

    facts = []
    for sentence in _SENTENCE_SPLIT_RE.split(content.strip()):
        refanged = refang(sentence)
        if any(m.lower() in refanged.lower() for m in markers):
            facts.append(sentence.strip())
        if len(facts) >= max_facts:
            break
    return facts


def compute_intel_dedup_key(cves: list[str], techniques: list[str], title: str) -> str:
    """
    dedup ข้ามแหล่งข่าว (ARCHITECTURE.md §3 ขั้นที่ 2) — เรื่องเดียวกันจากคนละสำนัก
    ต้องได้ key เดียวกัน จึง hash จากสาระของเรื่อง ไม่ใช่ title/URL ที่ต่างกันทุกสำนัก:
      1. มี CVE → key จากชุด CVE (สัญญาณข้ามสำนักที่แรงสุด — advisory เรื่องเดียวกันอ้าง CVE ชุดเดียวกัน)
      2. ไม่มี CVE แต่มี technique → key จากชุด technique
      3. ไม่มีทั้งคู่ → key จาก title ที่ normalize แล้ว (dedup ได้แค่ในสำนักเดียวกัน — ยอมรับใน mock phase)
    ⚠️ heuristic นี้หยาบ: คนละแคมเปญที่อ้าง CVE ชุดเดียวกันจะชนกัน — ต้องรีวิวตอนต่อ feed จริง
    """
    if cves:
        raw = "cve::" + "_".join(sorted(cves))
    elif techniques:
        raw = "tech::" + "_".join(sorted(techniques))
    else:
        raw = "title::" + re.sub(r"\W+", "_", title.lower())
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_intel_record(raw: dict) -> IntelRecord:
    """ประกอบขั้นที่ 2 (normalize + dedup key) + 3 (สกัด IoCs/facts) เป็น IntelRecord เดียว — dedup lookup อยู่ฝั่งผู้เรียก (เหมือน build_case_record)"""
    t0 = now_iso()
    content = raw.get("content", "") or ""
    title = (raw.get("title", "") or "").strip() or "Untitled Threat Report"

    iocs, techniques = extract_intel_iocs(content + " " + title)
    facts = extract_intel_facts(content, iocs, techniques)
    dedup_key = compute_intel_dedup_key(iocs.cves, techniques, title)
    t1 = now_iso()

    return IntelRecord(
        intel_id=f"intel_{uuid.uuid4().hex[:12]}",
        pipeline="proactive",
        dedup_key=dedup_key,
        source=SourceInfo(type="cti_feed", ref=raw.get("link"), raw=raw),
        timestamps=Timestamps(t0_ingested=t0, t1_normalized=t1),
        feed_name=raw.get("source", "unknown_feed"),
        title=title,
        link=raw.get("link"),
        published=raw.get("published"),
        threat_name=title,
        mitre_techniques=techniques,
        iocs=iocs,
        facts=facts,
        content_excerpt=(content[:500] + "…") if len(content) > 500 else content,
    )
