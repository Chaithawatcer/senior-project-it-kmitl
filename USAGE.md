# วิธีใช้งาน Omnissiah (สถานะปัจจุบัน)

> ขอบเขตที่ทำได้ตอนนี้: **Pipeline 1 เชิงรับ** แบบ manual trigger + mock Wazuh alert
> ยังไม่มี: Pipeline 2 (RSS), CTI enrichment (VirusTotal/AbuseIPDB), Teams/LINE notification, Review Gate

---

## 1. โครงสร้างไฟล์

ทุกคำสั่งในเอกสารนี้รันจาก **root ของ repo** (โฟลเดอร์ที่มี `requirements.txt`) — path ทั้งหมดเป็น relative จึงใช้ได้เหมือนกันทุกเครื่อง

```
<repo root>/
├─ requirements.txt          Python dependencies
├─ ARCHITECTURE.md           สถาปัตยกรรมเป้าหมาย 6 layers
├─ n8n-workflow.json         workflow สำหรับ import เข้า n8n
└─ Project/
   ├─ 01_ingest.py           อ่าน playbooks/*.md → chunk → embed → ChromaDB
   ├─ api.py                 FastAPI 5 endpoints ให้ n8n เรียก
   ├─ playbooks/*.md         Knowledge Base (3 ไฟล์)
   └─ chroma_db/             vector store (ถูกสร้างโดย 01_ingest.py)
```

---

## 2. ติดตั้งครั้งแรก

```bash
git clone https://github.com/Chaithawatcer/senior-project-it-kmitl.git
cd senior-project-it-kmitl
python -m venv .venv
```

activate venv (เลือกตามระบบ):

| ระบบ | คำสั่ง |
|---|---|
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Windows CMD | `.venv\Scripts\activate.bat` |
| macOS / Linux | `source .venv/bin/activate` |

แล้วติดตั้ง:

```bash
pip install -r requirements.txt
```

ถ้า PowerShell บล็อก script: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` แล้ว activate ใหม่

macOS/Linux บางเครื่องต้องใช้ `python3` แทน `python`

> ครั้งแรกที่รัน `01_ingest.py` ChromaDB จะดาวน์โหลด embedding model `all-MiniLM-L6-v2` (~80 MB) อัตโนมัติ ต้องต่อเน็ต
>
> `.venv/` และ `chroma_db/` เป็นของใครของมัน ไม่ต้อง commit — แต่ละคนสร้างเองบนเครื่องตัวเอง

---

## 3. ลำดับการรัน

### ขั้นที่ 1 — Ingest Knowledge Base

```bash
cd Project
python 01_ingest.py
```

ผลลัพธ์: ตารางสรุปจำนวน chunks แยกตาม phase และโฟลเดอร์ `chroma_db/` ถูกสร้าง

**ต้องรันขั้นนี้ก่อนเสมอ** — `api.py` ใช้ `get_collection()` ถ้ายังไม่มี collection ชื่อ `omnissiah_procedures` จะ crash ตอน startup ทันที

รันซ้ำเมื่อไหร่: ทุกครั้งที่แก้ไฟล์ใน `playbooks/` (สคริปต์ลบ collection เก่าทิ้งแล้วสร้างใหม่ทั้งหมด)

### ขั้นที่ 2 — เปิด API server

ตั้ง API key ก่อน (ทีมต้องนัดใช้ค่าเดียวกัน):

| ระบบ | คำสั่ง |
|---|---|
| PowerShell | `$env:OMNISSIAH_API_KEY = "รหัสลับของทีม"` |
| CMD | `set OMNISSIAH_API_KEY=รหัสลับของทีม` |
| macOS / Linux | `export OMNISSIAH_API_KEY="รหัสลับของทีม"` |

แล้วรัน (อยู่ในโฟลเดอร์ `Project/`):

```bash
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

เช็คว่าขึ้นแล้ว: เปิด http://localhost:8000/docs (Swagger UI ของ FastAPI)

ถ้าไม่ตั้ง `OMNISSIAH_API_KEY` ค่า default คือ `REPLACE_WITH_SHARED_SECRET` — ใช้ทดสอบได้แต่อย่าปล่อยไว้ตอนส่งจริง

### ขั้นที่ 3 — Import workflow เข้า n8n

1. เปิด n8n → เมนู ⋯ มุมขวาบน → **Import from File** → เลือก `n8n-workflow.json`
2. แก้ค่าใน 4 node นี้ให้ตรงกับที่ตั้งไว้ขั้นที่ 2 (header `X-API-Key`):
   `Get Sections`, `Retrieve Chunks`, `Assemble Playbook`, `Save Draft`
3. node `Gemini Generate` → แก้ header `x-goog-api-key` จาก `Gemini-API` เป็น API key จริงจาก Google AI Studio
4. กด **Execute Workflow** (Manual Trigger)

---

## 4. เรื่อง network ระหว่าง n8n กับ API

workflow ตั้ง URL เป็น `http://host.docker.internal:8000` ซึ่งแปลว่า **n8n รันใน Docker ส่วน API รันบน Windows โดยตรง**

| n8n รันแบบไหน | ต้องแก้ URL เป็น |
|---|---|
| Docker (ค่าปัจจุบัน) | `http://host.docker.internal:8000` — ใช้ได้เลย |
| ติดตั้งด้วย npm บนเครื่องเดียวกัน | `http://localhost:8000` |
| n8n Cloud | ต้องเปิด tunnel (เช่น ngrok) แล้วใช้ URL สาธารณะ |

ถ้า n8n อยู่ใน Docker ต้องรัน uvicorn ด้วย `--host 0.0.0.0` (ไม่ใช่ `127.0.0.1`) ไม่งั้น container เข้าไม่ถึง

---

## 5. Flow การทำงาน 13 node

```
Manual Trigger
  → Mock Wazuh Alert        สร้าง alert ปลอม: sshd brute force, rule 5763, T1110
  → Normalize Alert         Wazuh schema → job payload (job_id, threat_name, technique_ids, severity)
  → Get Sections            GET /template/sections   ได้ 5 phase
  → Split Out Sections      แตกเป็น 5 item
  ┌─ วนต่อ phase ─────────────────────────────────┐
  │ → Retrieve Chunks       POST /retrieve         ค้น ChromaDB ตาม phase + technique
  │ → Rate Guard            หน่วงเวลากัน Gemini rate limit
  │ → Build Prompt          fill_instruction + alert context + RAG chunks
  │ → Gemini Generate       gemini-flash-lite-latest
  │ → Extract Section       ดึงข้อความออกจาก response
  └────────────────────────────────────────────────┘
  → Aggregate Sections      รวม 5 phase
  → Assemble Playbook       POST /playbooks/assemble   ได้ markdown
  → Save Draft              POST /playbooks            เก็บสถานะ draft
```

ผลลัพธ์สุดท้ายอยู่ใน output ของ node `Save Draft` — คลิกดูใน n8n ได้เลย

---

## 6. API endpoints

ทุกตัวต้องส่ง header `X-API-Key` ยกเว้นจะโดน 401

| Method | Path | หน้าที่ |
|---|---|---|
| GET | `/template/sections` | คืนโครง 5 phase พร้อม fill_instruction |
| POST | `/retrieve` | hybrid retrieval — กรอง `phase` ที่ Chroma แล้วกรอง `technique_ids` ที่ Python |
| POST | `/playbooks/assemble` | ประกอบ markdown + แปะธง DRAFT / Coverage Warning |
| GET | `/playbooks/lookup` | เช็ค dedup ด้วย `technique_ids` + `threat_name` |
| POST | `/playbooks` | บันทึก playbook |

วิธีทดสอบที่ง่ายที่สุดและใช้ได้ทุกระบบ: เปิด http://localhost:8000/docs แล้วกด **Authorize** / ใส่ header `X-API-Key` ผ่าน Swagger UI

หรือทดสอบผ่าน command line:

```bash
# macOS / Linux
curl -H "X-API-Key: $OMNISSIAH_API_KEY" http://localhost:8000/template/sections

curl -X POST http://localhost:8000/retrieve \
  -H "X-API-Key: $OMNISSIAH_API_KEY" -H "Content-Type: application/json" \
  -d '{"phase":"containment","technique_ids":["T1110.001"],"query":"block source ip","top_k":3}'
```

```powershell
# Windows PowerShell
curl.exe -H "X-API-Key: $env:OMNISSIAH_API_KEY" http://localhost:8000/template/sections

curl.exe -X POST http://localhost:8000/retrieve `
  -H "X-API-Key: $env:OMNISSIAH_API_KEY" -H "Content-Type: application/json" `
  -d '{\"phase\":\"containment\",\"technique_ids\":[\"T1110.001\"],\"query\":\"block source ip\",\"top_k\":3}'
```

---

## 7. เพิ่ม playbook ใหม่เข้า Knowledge Base

สร้างไฟล์ `.md` ใน `Project/playbooks/` ตามรูปแบบนี้:

```markdown
---
threat_name: Brute Force
technique_ids: ["T1110.001", "T1110.003", "T1078"]
severity: Medium
source_doc: Brute_Force_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เนื้อหา...

### Sub: team_roles [T1078]
- ถ้าใส่ T-code ท้ายชื่อ Sub จะ override technique ของทั้งไฟล์เฉพาะ chunk นี้
```

กติกา:

- **ต้องมี frontmatter** ไม่งั้นไฟล์ถูกข้ามพร้อม warning สีเหลือง
- `## Phase:` ต้องใช้ชื่อตรงกับ 5 ค่านี้: `preparation`, `detection`, `containment`, `eradication`, `post_incident` — ถ้าสะกดไม่ตรง `/retrieve` จะกรองไม่เจอและคืน chunks ว่าง
- 1 `### Sub:` = 1 chunk
- แก้เสร็จต้องรัน `python 01_ingest.py` ใหม่

---

## 8. ปัญหาที่เจอบ่อย

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `uvicorn is not recognized` | ยังไม่ activate venv — ใช้ `python -m uvicorn` แทน |
| API crash ตอน startup | ยังไม่ได้รัน `01_ingest.py` หรือ path `chroma_db/` ไม่ตรง |
| 401 invalid api key | `OMNISSIAH_API_KEY` ในเครื่องไม่ตรงกับ header ใน n8n |
| n8n ต่อ API ไม่ได้ | uvicorn ผูกกับ `127.0.0.1` แทน `0.0.0.0` หรือ URL ไม่ตรงกับวิธีรัน n8n (ดูข้อ 4) |
| `chunks: []` + `missing_techniques` เต็ม | technique ใน alert ไม่มีใน KB — พฤติกรรมนี้ตั้งใจ ไม่มี silent fallback ระบบจะแปะธง ⚠️ แทนการเดา |
| retrieval คืนผลมั่วโดยไม่ error | เปลี่ยน embedding model หลัง ingest — ต้องใช้ตัวเดียวกันทั้ง `01_ingest.py` และ `api.py` แล้ว ingest ใหม่ |
| Gemini ตอบ 429 | เพิ่มเวลาหน่วงใน node `Rate Guard` |

---

## 9. ข้อจำกัดที่ต้องรู้

- `_STORE` ใน `api.py` เป็น dict ในหน่วยความจำ — **restart แล้วข้อมูลหายหมด** ยังไม่ได้ต่อฐานข้อมูลจริง
- `fallback_used` hardcode เป็น `False` ตลอด
- Coverage tier (full / partial / none) ตาม ARCHITECTURE.md §4.4 ยังไม่ได้ implement — ตอนนี้มีแค่ `missing_techniques`
- ยังไม่มี webhook endpoint รับ alert จริง — ใช้ Mock node ใน n8n แทน
