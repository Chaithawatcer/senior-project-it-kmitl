"""
api.py — Omnissiah FastAPI wrapper (v2)
ยก retrieval logic จาก poc/02_generate.py มาทำเป็น HTTP endpoint ให้ n8n เรียก

รัน:  uvicorn api:app --host 0.0.0.0 --port 8000
"""

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from central_schema import AlertIngestRequest, build_case_record

# --- Config ---
CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"
API_KEY = os.getenv("OMNISSIAH_API_KEY", "REPLACE_WITH_SHARED_SECRET")
# ⚠️ ห้าม hardcode ค่าจริงตรงนี้หรือที่ไหนในโค้ดเด็ดขาด — ตั้งเป็น env var ก่อนรัน uvicorn เท่านั้น
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ⚠️ ต้องเป็นตัวเดียวกับตอน ingest เป๊ะๆ (all-MiniLM-L6-v2)
#    ถ้าเปลี่ยน model retrieval จะพังเงียบๆ — คืน chunk มั่วโดยไม่ error
EMBEDDING_FN = embedding_functions.DefaultEmbeddingFunction()

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # สร้าง client ครั้งเดียวตอน startup — ไม่ใช่ต่อ request (ช้า + เสี่ยง lock)
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    state["collection"] = client.get_collection(
        name=COLLECTION_NAME, embedding_function=EMBEDDING_FN
    )
    yield
    state.clear()


app = FastAPI(title="Omnissiah RAG API", lifespan=lifespan)


def verify_key(x_api_key: str = Header(default="")):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")


# ---------------------------------------------------------------- alerts (Pipeline 1 เชิงรับ ขั้น 1-3)

# ⚠️ ครอบคลุมเฉพาะ ARCHITECTURE.md §2 ขั้นที่ 1-3: รับ alert (webhook) → normalize เป็น
# Central Schema + dedup + t0/t1 → สกัด observables — ขั้นที่ 4 เป็นต้นไป (CTI enrichment,
# NCSC/Escalation, RAG playbook, Notification/Review Gate) ยังไม่เชื่อมกับ endpoint นี้
# ในรอบนี้โดยตั้งใจ (ทำทีละท่อ ไม่ทำรวดเดียวทั้งเส้น)

_CASES: dict[str, dict] = {}  # dedup_key -> CaseRecord (dict) — ในหน่วยความจำ เหมือน _STORE ของ playbooks


@app.post("/alerts/ingest", dependencies=[Depends(verify_key)])
def ingest_alert(req: AlertIngestRequest):
    """
    [1] รับ mock SIEM alert ผ่าน webhook — endpoint นี้เอง (n8n Webhook node เรียกมาตรง ๆ)
    [2] Normalize → Central Schema, ประทับ t0-t1, ตรวจ dedup
    [3] สกัด observables (IP, hash, account, host)

    ถ้าเคยเห็น case ที่ dedup_key เดียวกันมาแล้ว คืนของเดิมทันที ไม่สร้าง case ใหม่
    (เหตุผลเดียวกับ dedup ของ playbook — SIEM ยิง alert ซ้ำสำหรับเหตุการณ์ต่อเนื่องเดียวกันได้)
    """
    raw = req.model_dump()
    case = build_case_record(raw)

    existing = _CASES.get(case.dedup_key)
    if existing:
        return {"status": "dedup_hit", "case": existing}

    case_dict = case.model_dump()
    _CASES[case.dedup_key] = case_dict
    return {"status": "created", "case": case_dict}


@app.get("/alerts/{case_id}", dependencies=[Depends(verify_key)])
def get_case(case_id: str):
    for case in _CASES.values():
        if case["case_id"] == case_id:
            return case
    raise HTTPException(status_code=404, detail="case not found")


# ---------------------------------------------------------------- CTI enrichment (ARCHITECTURE.md ขั้นที่ 4)

# เกณฑ์แปลงผลเป็น cti_verdict ตาม study/05-cti-enrichment-apis.md ของทีม


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _check_virustotal(ip: str) -> dict | None:
    if not VIRUSTOTAL_API_KEY:
        return None
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": attrs.get("reputation"),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        return {"error": str(e)}


def _check_abuseipdb(ip: str) -> dict | None:
    if not ABUSEIPDB_API_KEY:
        return None
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        d = data.get("data", {})
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "is_tor": d.get("isTor", False),
            "total_reports": d.get("totalReports", 0),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        return {"error": str(e)}


class CtiEnrichRequest(BaseModel):
    ip: str = ""


@app.post("/cti/enrich", dependencies=[Depends(verify_key)])
def cti_enrich(req: CtiEnrichRequest):
    """
    เช็ค IP กับ VirusTotal + AbuseIPDB แปลงเป็น cti_verdict ให้ /assess/severity ใช้ต่อ
    เกณฑ์: malicious = VT malicious>=5 หรือ AbuseIPDB score>=75
           suspicious = VT malicious 1-4 หรือ score 25-74 หรือ isTor
           clean      = นอกเหนือจากนั้น (ต้องเช็คได้จริงอย่างน้อย 1 แหล่ง)
           unknown    = ไม่มี IP ให้เช็ค หรือไม่ได้ตั้ง API key ไว้เลยสักตัว
    """
    ip = (req.ip or "").strip()
    if not ip:
        return {"ip": ip, "cti_verdict": "unknown", "virustotal": None, "abuseipdb": None,
                "reason": "ไม่มี IP ให้ตรวจสอบ"}

    if _is_private_ip(ip):
        return {"ip": ip, "cti_verdict": "clean", "virustotal": None, "abuseipdb": None,
                "reason": "internal/private IP — ข้าม enrichment"}

    vt = _check_virustotal(ip)
    abuse = _check_abuseipdb(ip)

    if vt is None and abuse is None:
        return {"ip": ip, "cti_verdict": "unknown", "virustotal": None, "abuseipdb": None,
                "reason": "ไม่ได้ตั้ง VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY ไว้เลย"}

    vt_malicious = vt.get("malicious", 0) if vt and "error" not in vt else 0
    abuse_score = abuse.get("score", 0) if abuse and "error" not in abuse else 0
    is_tor = abuse.get("is_tor", False) if abuse and "error" not in abuse else False

    if vt_malicious >= 5 or abuse_score >= 75:
        verdict = "malicious"
    elif vt_malicious >= 1 or 25 <= abuse_score < 75 or is_tor:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "ip": ip,
        "cti_verdict": verdict,
        "virustotal": vt,
        "abuseipdb": abuse,
        "reason": f"vt_malicious={vt_malicious}, abuseipdb_score={abuse_score}, is_tor={is_tor}",
    }


# ---------------------------------------------------------------- template

# ⚠️ ต้องมีแค่ 3 phase ตรงกับขอบเขต proposal §3.3 และ ARCHITECTURE.md §2 ขั้นที่ 7
#    (Containment → Eradication → Recovery) — ห้ามเพิ่มกลับเป็น 5 phase แบบ NIST lifecycle
#    ถ้าจะเพิ่ม phase ใหม่ ต้องได้รับอนุมัติเปลี่ยนขอบเขตจากอาจารย์ที่ปรึกษาก่อน
SECTIONS = [
    {
        "phase": "containment",
        "heading": "Phase 1: Containment",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | ขั้นตอน | คำสั่ง/การกระทำ | ความเสี่ยง | "
            "แยกเป็น short-term containment (หยุดผลกระทบทันที) และ long-term containment "
            "(กันไม่ให้กลับมาซ้ำระหว่างที่ยังสอบสวนไม่จบ)"
        ),
    },
    {
        "phase": "eradication",
        "heading": "Phase 2: Eradication",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | ขั้นตอน | รายละเอียด | เกณฑ์ยืนยันว่าสำเร็จ |\n"
            "เนื้อหา: กำจัดต้นตอ (บัญชี/มัลแวร์/persistence ที่ผู้โจมตีสร้างไว้) และปิดช่องโหว่ที่ถูกใช้โจมตี"
        ),
    },
    {
        "phase": "recovery",
        "heading": "Phase 3: Recovery",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | ขั้นตอน | รายละเอียด | ผู้ตรวจสอบ/อนุมัติ |\n"
            "เนื้อหา: การทำให้ระบบกลับมาใช้งานได้ตามปกติอย่างปลอดภัย การตรวจยืนยันว่าไม่มีร่องรอยหลงเหลือ "
            "และการเฝ้าระวังหลังเหตุการณ์ก่อนปิดเคส"
        ),
    },
]


@app.get("/template/sections", dependencies=[Depends(verify_key)])
def get_sections():
    # ห่อด้วย key "sections" เพื่อให้ n8n Split Out node มี field ให้แตก
    return {"sections": SECTIONS}


# ---------------------------------------------------------------- retrieve

class RetrieveRequest(BaseModel):
    phase: str
    technique_ids: list[str]
    query: str
    top_k: int = 5
    doc_types: list[str] | None = None  # None = ทุก doc_type; ใช้กรอง playbook/defense/mitre


@app.post("/retrieve", dependencies=[Depends(verify_key)])
def retrieve(req: RetrieveRequest):
    """
    Hybrid retrieval — ยกมาจาก query_rag() ใน 02_generate.py
      ชั้น 1: metadata pre-filter ด้วย phase (+ doc_type ถ้าระบุ) (Chroma ทำ)
      ชั้น 2: technique post-filter (Python ทำ — เพราะ Chroma ใช้ $contains กับ array ไม่ได้)
      ไม่มี silent fallback: ถ้าไม่ match technique เลย คืน chunks ว่าง แล้วให้ธง ⚠️ ขึ้น

    หมายเหตุ: ยังไม่ implement tiering เต็มรูปแบบ (primary/secondary ตาม doc_type)
    ตาม ARCHITECTURE.md §4 — ตอนนี้ doc_type เป็นแค่ filter ธรรมดา ไม่ได้ตัดสิน grounding tier
    """
    collection = state["collection"]

    where_clause: dict = {"phase": {"$eq": req.phase}}
    if req.doc_types:
        where_clause = {
            "$and": [
                {"phase": {"$eq": req.phase}},
                {"doc_type": {"$in": req.doc_types}},
            ]
        }

    results = collection.query(
        query_texts=[req.query],
        n_results=30,  # ดึงเผื่อ เพราะต้องกรองซ้ำฝั่ง Python
        where=where_clause,
        include=["documents", "metadatas"],
    )

    docs = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0] if results["metadatas"] else []

    chunks = []
    matched = set()
    for doc, meta in zip(docs, metas):
        chunk_techs = meta.get("technique_ids", "")
        hits = [t for t in req.technique_ids if t in chunk_techs]
        if hits:
            matched.update(hits)
            chunks.append({
                "text": doc,
                "source_doc": meta.get("source_doc", "unknown"),
                "threat_name": meta.get("threat_name", ""),
                "doc_type": meta.get("doc_type", "playbook"),
                "technique_ids": [t.strip() for t in chunk_techs.split(",") if t.strip()],
            })
        if len(chunks) >= req.top_k:
            break

    return {
        "phase": req.phase,
        "chunks": chunks,
        "matched_techniques": sorted(matched),
        "missing_techniques": [t for t in req.technique_ids if t not in matched],
        "fallback_used": False,
    }


# ---------------------------------------------------------------- severity (NCSC + Escalation Matrix)

# Rubric adapted จาก NCSC "Categorising UK cyber incidents" ลงมาระดับองค์กร
# (ต้นฉบับ NCSC มองระดับประเทศ C1-C2 — องค์กรเดี่ยวไม่มีทางถึงระดับนั้นจริง)
# อ้างอิงเกณฑ์เต็มใน study/03-ncsc-categorisation.md ของทีม
#
# ทำไมเป็น deterministic Python แทน "LLM node" ตามที่ ARCHITECTURE.md §2 ขั้นที่ 5 เขียนไว้:
# การตัดสิน category/escalation กระทบว่าใครถูกปลุกกลางดึกและ SLA เท่าไหร่ — ให้ LLM ตัดสินเอง
# มีความเสี่ยง hallucination ในจุดที่ผลกระทบสูงสุดของระบบ จึงย้าย logic นี้มาเป็นโค้ดที่ unit
# test ได้ ตรงกับหลักการที่ HANDOFF.md §4 ยึดอยู่แล้ว (logic ความปลอดภัยต้องอยู่ FastAPI ไม่ใช่
# ให้ LLM ตัดสินเอง) — ควรคุยกับทีม/อาจารย์ว่ายอมรับการเบี่ยงจากถ้อยคำเดิมใน ARCHITECTURE.md นี้ไหม

NCSC_LABELS = {
    "C2": "Highly Significant",
    "C3": "Significant",
    "C4": "Substantial",
    "C5": "Moderate",
    "C6": "Localised",
}

# จาก study/04-escalation-matrix-nist.md — ตัวเลข SLA เป็นค่าตั้งต้น ต้องยืนยันกับทีม/อาจารย์
ESCALATION_TABLE = {
    "C2": {"owner": "Incident Commander", "tier": 3, "sla_minutes": 15},
    "C3": {"owner": "Tier 2 (Incident Responder)", "tier": 2, "sla_minutes": 30},
    "C4": {"owner": "Tier 2 (Incident Responder)", "tier": 2, "sla_minutes": 60},
    "C5": {"owner": "Tier 1 (Triage Analyst)", "tier": 1, "sla_minutes": 240},
    "C6": {"owner": "Tier 1 (Triage Analyst)", "tier": 1, "sla_minutes": 1440},
}


class SeverityAssessRequest(BaseModel):
    account_privilege: str  # "domain_admin" | "privileged" | "standard" | "unknown"
    attack_success: bool = False  # มี event ล็อกอินสำเร็จ (เช่น 4624) จาก IP/บัญชีเดียวกันหรือไม่
    distinct_accounts: int = 1  # >1 = เข้าข่าย spraying/ขอบเขตกว้าง
    # ⚠️ TODO: ตอนนี้ CTI enrichment (VirusTotal/AbuseIPDB) ยังไม่ implement (HANDOFF.md งานที่เหลือข้อ 4)
    # cti_verdict จึงมักเป็น "unknown" เสมอ — เมื่อต่อ CTI จริงแล้วให้ส่งค่า malicious/suspicious/clean มาแทน
    cti_verdict: str = "unknown"  # "malicious" | "suspicious" | "clean" | "unknown"


@app.post("/assess/severity", dependencies=[Depends(verify_key)])
def assess_severity(req: SeverityAssessRequest):
    """
    ตัดสิน NCSC category + Escalation Matrix แบบ rubric ตายตัว (ดู study/03, study/04)
    กติกา fail-safe: ข้อมูลไม่พอ/ไม่ชัดเจน -> เลือก category ที่สูงกว่าไว้ก่อนเสมอ
    """
    priv = req.account_privilege.lower()
    is_domain_admin = priv == "domain_admin"
    is_privileged = priv in ("domain_admin", "privileged")
    multi_account = req.distinct_accounts > 1

    # "unknown" (CTI ยังไม่ต่อจริง) ถือเป็นระดับกลาง ไม่ใช่ "clean" — กันประเมินต่ำเกินจริง
    verdict = req.cti_verdict.lower()
    is_bad = verdict in ("malicious", "suspicious", "unknown")
    is_malicious = verdict in ("malicious", "unknown")

    reasons = [
        f"account_privilege={req.account_privilege}",
        f"cti_verdict={req.cti_verdict}",
        f"attack_success={req.attack_success}",
        f"distinct_accounts={req.distinct_accounts}",
    ]
    if verdict == "unknown":
        reasons.append("⚠️ CTI enrichment ยังไม่ต่อจริง — ตีความ unknown เป็นระดับกลางเพื่อความปลอดภัย")

    if req.attack_success and is_privileged:
        category = "C2"
    elif is_domain_admin and is_malicious:
        category = "C3"
    elif req.attack_success and not is_privileged:
        category = "C3"
    elif is_privileged and is_bad:
        category = "C4"
    elif multi_account and is_bad:
        category = "C4"
    elif is_bad:
        category = "C5"
    else:
        category = "C6"

    esc = ESCALATION_TABLE[category]
    return {
        "ncsc_category": category,
        "category_name": NCSC_LABELS[category],
        "rationale": "; ".join(reasons),
        "escalation_owner": esc["owner"],
        "escalation_tier": esc["tier"],
        "sla_minutes": esc["sla_minutes"],
    }


# ---------------------------------------------------------------- assemble

class Section(BaseModel):
    phase: str
    heading: str
    content: str


class NcscAssessment(BaseModel):
    ncsc_category: str
    category_name: str
    rationale: str
    escalation_owner: str
    escalation_tier: int
    sla_minutes: int


class CtiResult(BaseModel):
    ip: str
    cti_verdict: str
    reason: str
    virustotal: dict | None = None
    abuseipdb: dict | None = None


class AssembleRequest(BaseModel):
    threat_name: str
    technique_ids: list[str]
    severity: str = "medium"
    alert: dict = {}
    sections: list[Section]
    missing_techniques: list[str] = []
    fallback_used: bool = False
    job_id: str | None = None
    ncsc: NcscAssessment | None = None  # ผลจาก POST /assess/severity — None ถ้ายังไม่เรียก
    cti: CtiResult | None = None  # ผลจาก POST /cti/enrich — None ถ้ายังไม่เรียก


@app.post("/playbooks/assemble", dependencies=[Depends(verify_key)])
def assemble(req: AssembleRequest):
    parts = [f"# 🛡️ Incident Response Playbook: {req.threat_name}", ""]

    if req.missing_techniques:
        parts += [
            "> [!WARNING]",
            "> **⚠️ Knowledge Coverage Warning**",
            f"> ไม่พบขั้นตอนรองรับ technique: {', '.join(req.missing_techniques)}",
            "> เนื้อหาส่วนที่เกี่ยวข้องอาจไม่มีข้อมูลจริงรองรับ — ต้องผ่านการตรวจสอบโดย analyst",
            "",
        ]

    parts += [
        "> [!CAUTION]",
        "> **สถานะ: DRAFT** — ยังไม่ผ่าน human review ห้ามนำไปใช้จริงก่อนได้รับการอนุมัติ",
        "",
        "## Alert Context",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Threat | {req.threat_name} |",
        f"| Severity | {req.severity} |",
        f"| Techniques | {', '.join(req.technique_ids)} |",
    ]
    for k, v in req.alert.items():
        parts.append(f"| {k} | {v} |")
    parts.append("")

    if req.cti:
        c = req.cti
        vt_mal = (c.virustotal or {}).get("malicious", "-") if c.virustotal else "-"
        abuse_score = (c.abuseipdb or {}).get("score", "-") if c.abuseipdb else "-"
        parts += [
            "## CTI Enrichment (Threat Intelligence)",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Source IP | {c.ip} |",
            f"| Verdict | {c.cti_verdict} |",
            f"| VirusTotal malicious | {vt_mal} |",
            f"| AbuseIPDB score | {abuse_score} |",
            f"| หมายเหตุ | {c.reason} |",
            "",
        ]

    if req.ncsc:
        n = req.ncsc
        parts += [
            "## NCSC Categorisation & Escalation Matrix",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| NCSC Category | {n.ncsc_category} — {n.category_name} |",
            f"| Rationale | {n.rationale} |",
            f"| Escalation Owner | {n.escalation_owner} |",
            f"| Escalation Tier | {n.escalation_tier} |",
            f"| SLA | {n.sla_minutes} นาที |",
            "",
        ]

    for sec in req.sections:
        parts += [f"## {sec.heading}", "", sec.content, ""]

    return {"markdown": "\n".join(parts)}


# ---------------------------------------------------------------- store

_STORE: dict = {}


def dedup_key(technique_ids: list[str], threat_name: str) -> str:
    norm = re.sub(r"\W+", "_", threat_name.lower())
    return f"{'_'.join(sorted(technique_ids))}::{norm}"


class SavePlaybook(BaseModel):
    threat_name: str
    technique_ids: list[str]
    severity: str = "medium"
    status: str = "draft"
    markdown: str
    missing_techniques: list[str] = []
    job_id: str | None = None
    ncsc_category: str | None = None
    escalation_tier: int | None = None
    case_id: str | None = None  # เชื่อมกลับไป CaseRecord จาก /alerts/ingest (ถ้ามี)


@app.get("/playbooks/lookup", dependencies=[Depends(verify_key)])
def lookup(technique_ids: str, threat_name: str):
    key = dedup_key(technique_ids.split(","), threat_name)
    pb = _STORE.get(key)
    return {"status": pb["status"] if pb else "none", "playbook": pb}


@app.post("/playbooks", dependencies=[Depends(verify_key)])
def save_playbook(req: SavePlaybook):
    key = dedup_key(req.technique_ids, req.threat_name)
    _STORE[key] = req.model_dump()
    return {"playbook_id": key, "status": req.status}