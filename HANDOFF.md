# HANDOFF — Omnissiah (AI-Driven SOC Copilot)

เอกสารส่งต่องาน สำหรับ **เพื่อนในทีมที่มาทำต่อ** และ **AI assistant ที่รับ context ใหม่**
อัปเดตล่าสุด: 2026-07-21

> ถ้าคุณเป็น AI assistant: อ่านไฟล์นี้ให้จบก่อนแก้โค้ด ส่วน §4 (ข้อตกลงที่ห้ามพัง) คือสิ่งที่แก้ผิดแล้วระบบพังเงียบ ๆ โดยไม่ error

---

## 1. อ่านอะไรก่อน

| ลำดับ | ไฟล์ | ได้อะไร |
|---|---|---|
| 1 | `ARCHITECTURE.md` | สถาปัตยกรรมเป้าหมาย 6 layers, 2 pipelines — **นี่คือปลายทาง ไม่ใช่ของที่มีอยู่จริง** |
| 2 | `HANDOFF.md` (ไฟล์นี้) | ของที่มีอยู่จริงตอนนี้ + เหตุผลเบื้องหลัง |
| 3 | `USAGE.md` | วิธีติดตั้งและรัน |
| 4 | `Project/api.py` | logic หลักทั้งหมดอยู่ที่นี่ ไฟล์เดียว 239 บรรทัด |
| 5 | `Project/01_ingest.py` | วิธี chunk เอกสารเข้า ChromaDB |
| 6 | `n8n-workflow.json` | orchestration 13 nodes |

---

## 2. สถานะปัจจุบัน — เทียบกับ ARCHITECTURE.md

| Layer ตาม §1 | สถานะ | หมายเหตุ |
|---|---|---|
| [1] Ingestion (Pipeline 1) | 🟡 mock | node `Mock Wazuh Alert` hardcode alert ไว้ ยังไม่มี webhook รับของจริง |
| [2] Normalization | 🟢 ทำแล้ว | node `Normalize Alert` — Wazuh schema → job payload |
| [3] Enrichment & Analysis | 🔴 ยังไม่ทำ | **ไม่มี** VirusTotal / AbuseIPDB / NCSC severity / Escalation Matrix |
| [4] RAG Core | 🟢 ทำแล้ว | ChromaDB + hybrid retrieval + วนทีละ phase ครบ |
| [5] Output & Notification | 🟡 ครึ่งเดียว | ประกอบ markdown ได้ แต่ไม่มี Teams / LINE |
| [6] Human Review Gate | 🔴 ยังไม่ทำ | มีแค่ field `status: "draft"` ไม่มีกลไกอนุมัติ |
| Pipeline 2 (เชิงรุก) | 🔴 ยังไม่เริ่ม | ไม่มีโค้ดเลยสักบรรทัด |

**สรุป: ตอนนี้พิสูจน์ได้แค่แกน RAG ว่า retrieval + generation ทีละ phase ใช้งานได้จริง** ซึ่งเป็นส่วนที่เสี่ยงที่สุดของโปรเจกต์ — เลือกทำก่อนโดยตั้งใจ

---

## 3. Knowledge Base ที่มีอยู่

3 playbooks · 41 chunks · ครบ 5 phase ทุกไฟล์

| ไฟล์ | threat_name | technique_ids | severity |
|---|---|---|---|
| `01_brute_force.md` | Brute Force | T1110.001, T1110.003, T1078 | Medium |
| `02_credential_dumping.md` | Credential Dumping | T1003.001, T1078, T1550.002 | Critical |
| `03_rdp_bruteforce.md` | RDP Brute Force | T1110.001, T1021.001, T1078 | High |

ครอบคลุมแค่ธีม **credential attack บน Active Directory** — นอกขอบเขตนี้ระบบจะคืน `chunks: []` แล้วแปะธง ⚠️ ซึ่งเป็นพฤติกรรมที่ถูกต้อง ไม่ใช่บั๊ก

---

## 4. ข้อตกลงที่ห้ามพัง (invariants)

ทุกข้อนี้ถ้าแก้ผิด **ระบบจะไม่ error แต่ผลลัพธ์จะมั่ว** — อันตรายกว่าพังตรง ๆ

### 4.1 embedding model ต้องเป็นตัวเดียวกันทั้ง ingest และ query

`01_ingest.py:25` และ `api.py:25` ใช้ `embedding_functions.DefaultEmbeddingFunction()` (= `all-MiniLM-L6-v2`) เหมือนกัน
ถ้าเปลี่ยนที่ใดที่หนึ่ง vector space จะคนละชุด → retrieval คืน chunk ที่ไม่เกี่ยวเลยโดยไม่มี error
**เปลี่ยนแล้วต้องรัน `01_ingest.py` ใหม่ทุกครั้ง**

### 4.2 ชื่อ phase ต้องตรง 5 ค่านี้เป๊ะ

`preparation` · `detection` · `containment` · `eradication` · `post_incident`

ผูกกัน 3 ที่: หัวข้อ `## Phase:` ในไฟล์ playbook → metadata ใน ChromaDB → `SECTIONS[].phase` ใน `api.py:51`
สะกดไม่ตรงแม้ตัวเดียว → `where={"phase": {"$eq": ...}}` กรองไม่เจอ → chunks ว่าง

### 4.3 ไม่มี silent fallback — โดยตั้งใจ

`api.py:115` เขียนไว้ชัด: ถ้าไม่ match technique เลย ให้คืน `chunks: []` แล้วปล่อยให้ธง ⚠️ ขึ้น
**ห้ามเติม fallback ที่คืน chunk ใกล้เคียงมาแทน** — เหตุผลคือ playbook ที่ดูสมบูรณ์แต่ไม่มีข้อมูลจริงรองรับ อันตรายกว่า playbook ที่บอกตรง ๆ ว่าไม่รู้

### 4.4 retrieval เป็น 2 ชั้นเสมอ

ชั้น 1 กรอง `phase` ที่ ChromaDB (`api.py:122`) → ชั้น 2 กรอง `technique_ids` ที่ Python (`api.py:131-134`)
ที่ต้องทำชั้น 2 ฝั่ง Python เพราะ ChromaDB ใช้ `$contains` กับ array ไม่ได้ จึงเก็บ technique เป็น comma-string แล้วกรองเอง
ดึงมา 30 แล้วค่อยตัดเหลือ `top_k` เพราะกรองซ้ำรอบสองจะเหลือน้อยกว่าที่ขอ

### 4.5 No Auto-Remediation

ระบบไม่ส่งคำสั่งไปยังอุปกรณ์เครือข่ายทุกกรณี output เป็น Draft เสมอ
นี่คือ **คุณสมบัติของสถาปัตยกรรม ไม่ใช่ข้อจำกัด** — เป็นเหตุผลที่ระบบปลอดภัยพอจะให้ LLM เขียนขั้นตอนได้

---

## 5. จุดที่ยังเปราะ / รู้ตัวแล้วแต่ยังไม่แก้

| จุด | รายละเอียด | ผลกระทบ |
|---|---|---|
| `_STORE` เป็น dict ใน RAM (`api.py:210`) | restart แล้วหายหมด | `/playbooks/lookup` ใช้ dedup ข้ามรอบไม่ได้จริง |
| technique match ใช้ substring (`api.py:133`) | `"T1110" in "T1110.001,..."` → True | parent technique match child ได้โดยบังเอิญ **แต่ทางกลับกันไม่ได้** — mock alert ส่ง `T1110` แล้ว match ติดเพราะเหตุนี้ ถ้าเปลี่ยนเป็น exact match ต้องแก้ทั้ง KB |
| `fallback_used` hardcode `False` (`api.py:150`) | field ตายอยู่ | `Aggregate Sections` อ่านค่านี้ไปแต่ได้ `false` ตลอด |
| Coverage tier §4.4 ของ ARCHITECTURE ยังไม่มี | ไม่มี full/partial/none, ไม่มี similarity threshold | ตอนนี้มีแค่ `missing_techniques` แบบ binary |
| ไม่มี dedup / `t0`–`t6` timestamp | ARCHITECTURE พูดถึงแต่โค้ดยังไม่มี | วัด MTTR ไม่ได้ |
| API key เป็น plaintext ใน `n8n-workflow.json` | ค่าปัจจุบันเป็น placeholder | **ห้าม commit key จริงลงไฟล์นี้เด็ดขาด** |
| `requirements.txt` ไม่ตรงกับ import จริง | `pymisp`, `python-frontmatter` ยังไม่ถูก import ที่ไหนเลย ส่วน `sentence-transformers` / `pydantic` ติดมาแบบ transitive ไม่ได้ประกาศตรง ๆ | ควรจัดให้ตรงก่อนส่ง |

---

## 6. งานที่เหลือ — เรียงตามลำดับที่ควรทำ

1. **แทน Mock ด้วย Webhook จริง** — เพิ่ม `POST /alerts` ใน `api.py` แล้วเปลี่ยน trigger ใน n8n เป็น Webhook node (งานเล็ก ปลดล็อกการทดสอบ end-to-end)
2. **Persist `_STORE`** — SQLite ก็พอ ใช้ `chroma.sqlite3` แยกไฟล์หรือไฟล์ใหม่ก็ได้ (แก้ `api.py` §store อย่างเดียว)
3. **Coverage tier** — implement §4.4 ของ ARCHITECTURE: ต้องเปิด `distances` ใน `include=[...]` ที่ `api.py:123` ก่อน แล้วหา threshold จากการทดลอง **อย่าตั้งค่าลอย ๆ**
4. **CTI enrichment** — VirusTotal / AbuseIPDB คั่นระหว่าง `Normalize Alert` กับ `Get Sections`
5. **NCSC severity + Escalation Matrix** — ตอนนี้ severity map จาก Wazuh level ตรง ๆ ยังไม่ใช่กรอบ NCSC
6. **Notification + Review Gate** — Teams / LINE + กลไก Draft → Approved
7. **Pipeline 2 (RSS)** — งานใหญ่สุด ทำท้ายสุด ใช้ RAG core ตัวเดิมได้เลย

---

## 7. เรื่องที่ยังไม่ได้ตัดสินใจ (ต้องคุยกันก่อนลงมือ)

- **จะย้ายไป `google-genai` SDK ไหม** — `requirements.txt` ยังใช้ `google-generativeai` ซึ่ง Google deprecate แล้ว ตอนนี้ n8n เรียก REST ตรงจึงยังไม่กระทบ แต่ถ้าจะเขียน LLM logic ฝั่ง Python ต้องเลือก
- **logic จะอยู่ที่ n8n หรือ FastAPI** — ตอนนี้ปนกัน (normalize + build prompt อยู่ n8n, retrieval + assemble อยู่ Python) คอมเมนต์ใน `Normalize Alert` เขียนว่า "ตอนขึ้นจริง FastAPI จะเป็นคนทำขั้นนี้" — ยังไม่ได้ย้าย
- **`pymisp` จะใช้จริงไหม** — อยู่ใน requirements แต่ ARCHITECTURE ระบุ VirusTotal / AbuseIPDB ไม่ใช่ MISP
- **จะรองรับ MITRE technique ระดับ parent หรือ sub เท่านั้น** — เกี่ยวกับ §5 เรื่อง substring match

---

## 8. ค่าที่ต้องตั้งเองก่อนรัน

| ค่า | ตั้งที่ไหน | ค่า placeholder ปัจจุบัน |
|---|---|---|
| `OMNISSIAH_API_KEY` | env บนเครื่อง + header `X-API-Key` ใน n8n 4 nodes | `REPLACE_WITH_SHARED_SECRET` |
| Gemini API key | header `x-goog-api-key` ใน node `Gemini Generate` | `Gemini-API` |
| Base URL ของ API | 4 HTTP Request nodes ใน n8n | `http://host.docker.internal:8000` (สมมติว่า n8n อยู่ใน Docker) |

รายละเอียดวิธีตั้งอยู่ใน `USAGE.md` §2–§4

---

## 9. พารามิเตอร์ที่ตั้งไว้ตอนนี้

| ค่า | ตั้งเป็น | ที่มา |
|---|---|---|
| LLM model | `gemini-flash-lite-latest` | node `Gemini Generate` |
| temperature | `0.2` | ต่ำ เพราะต้องการความสม่ำเสมอมากกว่าความสร้างสรรค์ |
| maxOutputTokens | `2048` | ต่อ 1 phase |
| `n_results` ที่ Chroma | `30` | ดึงเผื่อกรองรอบสอง |
| `top_k` ที่ส่งให้ LLM | `5` | |
| Rate Guard | หน่วง `2` วินาที | กัน Gemini 429 |
| chunk strategy | 1 `### Sub:` = 1 chunk | ไม่ได้ตัดตามจำนวน token |
| distance metric | `cosine` (`hnsw:space`) | |
