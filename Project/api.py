"""
api.py — Omnissiah FastAPI wrapper (v2)
ยก retrieval logic จาก poc/02_generate.py มาทำเป็น HTTP endpoint ให้ n8n เรียก

รัน:  uvicorn api:app --host 0.0.0.0 --port 8000
"""

import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

# --- Config ---
CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"
API_KEY = os.getenv("OMNISSIAH_API_KEY", "REPLACE_WITH_SHARED_SECRET")

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