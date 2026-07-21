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

SECTIONS = [
    {
        "phase": "preparation",
        "heading": "Phase 1: Preparation",
        "fill_instruction": (
            "สร้างตาราง Markdown ที่มี 3 คอลัมน์เท่านั้น: | ขั้นตอน | รายละเอียด | ผู้รับผิดชอบ |\n"
            "ห้ามเพิ่มหรือลดคอลัมน์ ห้ามใส่หัวข้อหรือคำอธิบายนอกตาราง\n"
            "เนื้อหา: สิ่งที่ต้องเตรียมล่วงหน้าก่อนเกิดเหตุ เช่น log source, tooling, baseline"
        ),
    },
    {
        "phase": "detection",
        "heading": "Phase 2: Detection & Analysis",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | สัญญาณบ่งชี้ | แหล่ง Log | วิธีตรวจสอบ | "
            "อ้างอิง Event ID และ IOC จาก alert context จริงถ้ามี"
        ),
    },
    {
        "phase": "containment",
        "heading": "Phase 3: Containment",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | ขั้นตอน | คำสั่ง/การกระทำ | ความเสี่ยง | "
            "แยกเป็น short-term และ long-term containment"
        ),
    },
    {
        "phase": "eradication",
        "heading": "Phase 4: Eradication & Recovery",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | ขั้นตอน | รายละเอียด | เกณฑ์ยืนยันว่าสำเร็จ |"
        ),
    },
    {
        "phase": "post_incident",
        "heading": "Phase 5: Post-Incident Activity",
        "fill_instruction": (
            "สร้างตาราง Markdown คอลัมน์: | หัวข้อ | สิ่งที่ต้องทบทวน | ผลลัพธ์ที่คาดหวัง |"
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


@app.post("/retrieve", dependencies=[Depends(verify_key)])
def retrieve(req: RetrieveRequest):
    """
    Hybrid retrieval — ยกมาจาก query_rag() ใน 02_generate.py
      ชั้น 1: metadata pre-filter ด้วย phase (Chroma ทำ)
      ชั้น 2: technique post-filter (Python ทำ — เพราะ Chroma ใช้ $contains กับ array ไม่ได้)
      ไม่มี silent fallback: ถ้าไม่ match technique เลย คืน chunks ว่าง แล้วให้ธง ⚠️ ขึ้น
    """
    collection = state["collection"]

    results = collection.query(
        query_texts=[req.query],
        n_results=30,  # ดึงเผื่อ เพราะต้องกรองซ้ำฝั่ง Python
        where={"phase": {"$eq": req.phase}},
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


# ---------------------------------------------------------------- assemble

class Section(BaseModel):
    phase: str
    heading: str
    content: str


class AssembleRequest(BaseModel):
    threat_name: str
    technique_ids: list[str]
    severity: str = "medium"
    alert: dict = {}
    sections: list[Section]
    missing_techniques: list[str] = []
    fallback_used: bool = False
    job_id: str | None = None


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