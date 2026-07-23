# วิธีใช้งาน Omnissiah (สถานะปัจจุบัน) (docker start omnissiah-n8n)

> ขอบเขตที่ทำได้ตอนนี้: **Pipeline 1 เชิงรับ** ครบทั้งเส้น demo (manual trigger + mock Wazuh alert →
> NCSC/Escalation → RAG playbook) **บวก webhook รับ alert จริงแยกต่างหาก** (`/alerts/ingest` — ดู §3.5)
> ที่ทำ Normalize → Central Schema + dedup + t0/t1 + สกัด observables ตาม ARCHITECTURE.md §2 ขั้น 1-3
> รวม **NCSC Categorisation + Escalation Matrix** แล้ว (deterministic, ดู HANDOFF.md §4.6)
> ยังไม่มี: Pipeline 2 (RSS), CTI enrichment (VirusTotal/AbuseIPDB — `cti_verdict` เป็น `"unknown"` เสมอตอนนี้), Teams/LINE notification, Review Gate, การเชื่อม `/alerts/ingest` เข้ากับ workflow สร้าง playbook เต็มเส้น (ยังเป็น 2 workflow แยกกัน — ดู §3.5)

---

## 1. โครงสร้างไฟล์

ทุกคำสั่งในเอกสารนี้รันจาก **root ของ repo** (โฟลเดอร์ที่มี `requirements.txt`) — path ทั้งหมดเป็น relative จึงใช้ได้เหมือนกันทุกเครื่อง

```
<repo root>/
├─ requirements.txt          Python dependencies
├─ ARCHITECTURE.md           สถาปัตยกรรมเป้าหมาย 6 layers
├─ n8n-workflow.json         workflow เชิงรับเต็มเส้น (mock alert → ingest → CTI → NCSC → RAG playbook)
├─ n8n-workflow-reactive-ingest.json  workflow แยก — Webhook จริง → /alerts/ingest
├─ n8n-workflow-proactive.json  workflow เชิงรุกเต็มเส้น (mock feed → dedup → RAG → notify) ⭐ ใหม่
└─ Project/
   ├─ central_schema.py      Central Schema ทั้ง 2 ท่อ: CaseRecord (เชิงรับ) + IntelRecord (เชิงรุก) ⭐ อัปเดต
   ├─ 01_ingest.py           อ่าน playbooks/**/*.md → chunk → embed → ChromaDB (รองรับ subfolder)
   ├─ gen_mitre_kb.py        ดึง MITRE Mitigations ทางการเข้า KB (ต้องดาวน์โหลด STIX data ก่อน)
   ├─ api.py                 FastAPI 12 endpoints ให้ n8n เรียก
   ├─ playbooks/*.md         Knowledge Base ส่วน threat playbook (3 ไฟล์, doc_type=playbook)
   ├─ playbooks/defense/     KB ส่วนเอกสารป้องกันรายเทคนิค (doc_type=defense)
   ├─ playbooks/mitre/       KB ส่วน MITRE Mitigations ทางการ (doc_type=mitre, สร้างโดย gen_mitre_kb.py)
   ├─ mitre_data/            STIX data ดิบ (~50MB, ไม่ commit — .gitignore ไว้แล้ว)
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

### ขั้นที่ 0 (ทำครั้งเดียว, ทางเลือก) — สร้าง MITRE Mitigations เข้า KB

```bash
cd Project
mkdir -p mitre_data
curl -L -o mitre_data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python gen_mitre_kb.py
```

สร้างไฟล์ `.md` ใน `playbooks/mitre/` จาก MITRE ATT&CK official Mitigations (offline หลังดาวน์โหลด STIX แล้ว) — ข้ามขั้นนี้ได้ถ้าไม่อยากรอโหลดไฟล์ 50MB แต่ KB จะไม่ครบ 3 ส่วนตาม proposal §3.2

### ขั้นที่ 1 — Ingest Knowledge Base

```bash
cd Project
python 01_ingest.py
```

ผลลัพธ์: ตารางสรุปจำนวน chunks แยกตาม phase และโฟลเดอร์ `chroma_db/` ถูกสร้าง (ตอนนี้ควรเห็น 3 phase: containment/eradication/recovery)

**ต้องรันขั้นนี้ก่อนเสมอ** — `api.py` ใช้ `get_collection()` ถ้ายังไม่มี collection ชื่อ `omnissiah_procedures` จะ crash ตอน startup ทันที

รันซ้ำเมื่อไหร่: ทุกครั้งที่แก้ไฟล์ใน `playbooks/` (สคริปต์ลบ collection เก่าทิ้งแล้วสร้างใหม่ทั้งหมด รวม subfolder `defense/` และ `mitre/`)

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
2. แก้ค่าใน **7 node** นี้ให้ตรงกับที่ตั้งไว้ขั้นที่ 2 (header `X-API-Key`):
   `Ingest Alert`, `CTI Enrichment`, `Assess Severity`, `Get Sections`, `Retrieve Chunks`, `Assemble Playbook`, `Save Draft`
3. node `Gemini Generate` → แก้ header `x-goog-api-key` จาก `Gemini-API` เป็น API key จริงจาก Google AI Studio
   (⚠️ คนละ header name กับ node อื่น — ห้าม copy header ของ node นี้ไปวาง node อื่น)
4. กด **Execute Workflow** (Manual Trigger)

### ขั้นที่ 3.5 — Reactive Ingest Workflow (webhook จริง)

`n8n-workflow-reactive-ingest.json` เป็น workflow **แยกต่างหาก** — สาธิตการรับ alert ผ่าน Webhook node
จริง (แทน Mock Wazuh Alert) เข้า `/alerts/ingest` เดียวกันกับ workflow หลัก ใช้ตอนจะต่อ SIEM จริง

1. Import `n8n-workflow-reactive-ingest.json` เข้า n8n เหมือนขั้นที่ 3
2. แก้ header `X-API-Key` ใน node `Ingest Alert` ให้ตรงกับที่ตั้งไว้
3. **Activate** workflow (toggle มุมขวาบนของหน้า editor — ต่างจาก `n8n-workflow.json` ที่ใช้ Manual Trigger กดรันเอง เพราะอันนี้ใช้ Webhook node ต้อง activate ก่อน webhook ถึงจะรับ request ได้จริง)
4. ยิง POST ไปที่ URL ที่ node `Webhook` แสดง (ปกติ `http://localhost:5678/webhook/alerts/ingest`) ด้วย mock Wazuh alert (ดูตัวอย่าง JSON ใน `Project/central_schema.py`'s `AlertIngestRequest` หรือใน HANDOFF.md)
5. ยิงซ้ำด้วย payload เดิมอีกครั้ง — ต้องได้ `"status": "dedup_hit"` คืน `case_id` เดิม เป็นการยืนยันว่า dedup ทำงาน

### ขั้นที่ 3.6 — Proactive Workflow (Pipeline 2 เชิงรุก, mock feed) ⭐ ใหม่

`n8n-workflow-proactive.json` คือ Pipeline 2 ทั้งเส้น: ข่าวกรองภัยคุกคาม → playbook ป้องกันล่วงหน้า +
ข้อความแจ้งผู้บริหาร + ข้อความแจ้งฝ่ายไอที — ตอนนี้ใช้ **Mock CTI Feed** (Code node) แทน RSS จริง
โดยจงใจใส่ข่าว 2 ชิ้นที่เป็น **เรื่องเดียวกันคนละสำนัก** (The Hacker News + CISA อ้าง CVE เดียวกัน)
เพื่อสาธิต dedup ข้ามแหล่งข่าว: ชิ้นแรก `created` ชิ้นที่สอง `dedup_hit` แล้วถูก Filter ตัดทิ้ง

1. Import `n8n-workflow-proactive.json` เข้า n8n
2. แก้ header `X-API-Key` ใน **6 node**: `Ingest Intel`, `Get Sections`, `Retrieve Chunks`,
   `Assemble Playbook`, `Save Draft`, `Notify Messages`
3. node `Gemini Generate` → ใส่ Gemini key จริง (header `x-goog-api-key` เหมือน workflow หลัก)
4. กด **Execute Workflow** — ผลลัพธ์สุดท้ายอยู่ที่ node `Prepare Notifications`:
   `playbook_id` + `executive_message` (ผู้บริหาร — ไม่มีศัพท์เทคนิค/IoC) + `it_message` (ฝ่ายไอที — technique + IoC แบบ defang + ขั้นตอนถัดไป)

ของจริงในอนาคต: แทน `Manual Trigger`+`Mock CTI Feed` ด้วย **Schedule Trigger + RSS Read** แล้วต่อ
`Prepare Notifications` เข้า Teams/LINE node — logic ที่เหลือไม่ต้องแก้เลย

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

## 5. Flow การทำงาน

### 5.1 เชิงรับ — `n8n-workflow.json` (15 node)

```
Manual Trigger
  → Mock Wazuh Alert        สร้าง alert ปลอม: Windows AD Event 4625+4740, admin_somchai, T1110.001
  → Ingest Alert            POST /alerts/ingest     normalize → CaseRecord + dedup + t0/t1 + observables
  → CTI Enrichment          POST /cti/enrich        เช็ค IP กับ VirusTotal + AbuseIPDB → cti_verdict
  → Assess Severity         POST /assess/severity   ได้ NCSC category + Escalation Matrix (ใช้ cti_verdict จริง)
  → Get Sections            GET /template/sections   ได้ 3 phase (containment/eradication/recovery)
  → Split Out Sections      แตกเป็น 3 item
  ┌─ วนต่อ phase ─────────────────────────────────┐
  │ → Retrieve Chunks       POST /retrieve         ค้น ChromaDB ตาม phase + technique (+ doc_type ถ้าระบุ)
  │ → Rate Guard            หน่วงเวลากัน Gemini rate limit
  │ → Build Prompt          fill_instruction + alert context + RAG chunks
  │ → Gemini Generate       gemini-flash-lite-latest
  │ → Extract Section       ดึงข้อความออกจาก response
  └────────────────────────────────────────────────┘
  → Aggregate Sections      รวม 3 phase + แนบผล CTI + Assess Severity
  → Assemble Playbook       POST /playbooks/assemble   ได้ markdown (มี CTI + NCSC/Escalation table)
  → Save Draft              POST /playbooks            เก็บสถานะ draft + ncsc_category + escalation_tier
```

ผลลัพธ์สุดท้ายอยู่ใน output ของ node `Save Draft` — คลิกดูใน n8n ได้เลย

### 5.2 เชิงรุก — `n8n-workflow-proactive.json` (17 node) ⭐ ใหม่

```
Manual Trigger
  → Mock CTI Feed           ข่าว 2 ชิ้น "เรื่องเดียวกันคนละสำนัก" (Hacker News + CISA, CVE เดียวกัน)
  → Ingest Intel            POST /intel/ingest      normalize → IntelRecord + dedup ข้ามแหล่งข่าว
                                                     + สกัด facts (verbatim) / IoCs / techniques
  → Filter New Intel        เอาเฉพาะ status=created (ข่าวซ้ำโดน dedup_hit ตัดทิ้งตรงนี้)
  → Limit 1 Story           กัน Gemini ถูกยิงหลายเรื่องในรอบ demo เดียว
  → Get Sections            GET /template/sections?pipeline=proactive  ได้ 3 sections เชิงป้องกัน
  → Split Out Sections      แตกเป็น 3 item
  ┌─ วนต่อ section ────────────────────────────────┐
  │ → Retrieve Chunks       POST /retrieve          doc_types: ["defense","mitre"] (บริบทเชิงป้องกัน)
  │ → Rate Guard → Build Prompt (facts+IoCs+chunks) → Gemini Generate → Extract Section
  └────────────────────────────────────────────────┘
  → Aggregate Sections      รวม 3 sections + intel_source + iocs
  → Assemble Playbook       POST /playbooks/assemble   ได้ Proactive Defense Playbook + IoC table (defanged)
  → Save Draft              POST /playbooks
  → Notify Messages         POST /notify/messages      สร้างข้อความผู้บริหาร + ข้อความฝ่ายไอที
  → Prepare Notifications   ก้อนสุดท้าย: playbook_id + executive_message + it_message
```

ผลลัพธ์สุดท้ายอยู่ใน output ของ node `Prepare Notifications`

---

## 6. API endpoints

ทุกตัวต้องส่ง header `X-API-Key` ยกเว้นจะโดน 401

| Method | Path | หน้าที่ |
|---|---|---|
| POST | `/alerts/ingest` | เชิงรับ [1-3] — รับ SIEM alert → normalize เป็น CaseRecord + dedup + t0/t1 + สกัด observables |
| GET | `/alerts/{case_id}` | ดึง case ที่ ingest ไว้ด้วย case_id |
| POST | `/intel/ingest` | ⭐ ใหม่ — เชิงรุก [1-3]: รับข่าวจาก feed → IntelRecord + dedup ข้ามแหล่งข่าว + สกัด facts (verbatim)/IoCs/techniques |
| GET | `/intel/{intel_id}` | ⭐ ใหม่ — ดึง intel record ที่ ingest ไว้ |
| POST | `/cti/enrich` | เช็ค IP กับ VirusTotal + AbuseIPDB → `cti_verdict` (ต้องตั้ง env key ทั้งสอง ไม่งั้นได้ `unknown`) |
| GET | `/template/sections` | คืนโครง 3 sections — default เชิงรับ (Phase 1-3), `?pipeline=proactive` ได้ชุดเชิงป้องกัน (Part 1-3) |
| POST | `/assess/severity` | NCSC Categorisation (C2–C6) + Escalation Matrix แบบ deterministic |
| POST | `/retrieve` | hybrid retrieval — กรอง `phase` (+ `doc_types` ถ้าระบุ) ที่ Chroma แล้วกรอง `technique_ids` ที่ Python |
| POST | `/playbooks/assemble` | ประกอบ markdown + ธง DRAFT / Coverage Warning / CTI / NCSC-Escalation — ฝั่งรุกส่ง `playbook_type: "proactive"` + `intel_source` + `iocs` ได้ IoC table (defanged) |
| GET | `/playbooks/lookup` | เช็ค dedup ด้วย `technique_ids` + `threat_name` |
| POST | `/playbooks` | บันทึก playbook (รวม `ncsc_category`, `escalation_tier`, `case_id`/`intel_id`) |
| POST | `/notify/messages` | ⭐ ใหม่ — สร้างข้อความแจ้ง 2 ฉบับ: ผู้บริหาร (ไม่มีศัพท์เทคนิค) + ฝ่ายไอที (technique/IoC defanged/ขั้นตอน) — deterministic template ไม่ใช่ LLM |

> `/alerts/ingest` กับ `/playbooks/lookup` เป็น dedup คนละชั้นกัน — `/alerts/ingest` กัน SIEM alert ซ้ำ
> ตั้งแต่ต้นทาง (ก่อนรู้ด้วยซ้ำว่าจะสร้าง playbook ไหม) ส่วน `/playbooks/lookup` กัน generate playbook
> ซ้ำสำหรับ technique ชุดเดียวกัน — คนละ dedup_key คนละ store กัน (`_CASES` vs `_STORE`)

วิธีทดสอบที่ง่ายที่สุดและใช้ได้ทุกระบบ: เปิด http://localhost:8000/docs แล้วกด **Authorize** / ใส่ header `X-API-Key` ผ่าน Swagger UI

หรือทดสอบผ่าน command line:

```bash
# macOS / Linux
curl -H "X-API-Key: $OMNISSIAH_API_KEY" http://localhost:8000/template/sections

curl -X POST http://localhost:8000/retrieve \
  -H "X-API-Key: $OMNISSIAH_API_KEY" -H "Content-Type: application/json" \
  -d '{"phase":"containment","technique_ids":["T1110.001"],"query":"block source ip","top_k":3}'

curl -X POST http://localhost:8000/assess/severity \
  -H "X-API-Key: $OMNISSIAH_API_KEY" -H "Content-Type: application/json" \
  -d '{"account_privilege":"domain_admin","attack_success":false,"distinct_accounts":1,"cti_verdict":"unknown"}'

curl -X POST http://localhost:8000/alerts/ingest \
  -H "X-API-Key: $OMNISSIAH_API_KEY" -H "Content-Type: application/json" \
  -d '{
    "rule": {"level": 10, "description": "Multiple Windows Logon Failures", "id": "60122",
      "mitre": {"id": ["T1110.001"], "technique": ["Brute Force: Password Guessing"]}},
    "agent": {"name": "DC01"},
    "data": {"win": {"system": {"eventID": "4625"},
      "eventdata": {"targetUserName": "admin_somchai", "ipAddress": "185.15.58.22", "logonType": "3", "subStatus": "0xC000006A"}}},
    "full_log": "test alert"
  }'
# ยิงซ้ำด้วย body เดิม -> ต้องได้ "status": "dedup_hit" คืน case_id เดิม

# เชิงรุก: ingest ข่าวจาก CTI feed (mock) — ระบบสกัด IoCs/CVE/techniques + facts ให้เอง
curl -X POST http://localhost:8000/intel/ingest \
  -H "X-API-Key: $OMNISSIAH_API_KEY" -H "Content-Type: application/json" \
  -d '{
    "source": "The Hacker News",
    "title": "New Brute-Force Campaign Targets Active Directory",
    "link": "https://example.com/news",
    "content": "Attackers perform password spraying (T1110.003) from 45.155.205[.]233. Patch CVE-2025-21298 urgently."
  }'
# ยิงข่าว "เรื่องเดียวกันจากสำนักอื่น" (อ้าง CVE ชุดเดียวกัน) -> ต้องได้ "status": "dedup_hit"
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

สร้างไฟล์ `.md` ใน `Project/playbooks/` (หรือ `playbooks/defense/` ถ้าเป็นเอกสารรายเทคนิคไม่ผูก threat) ตามรูปแบบนี้:

```markdown
---
threat_name: Brute Force
technique_ids: ["T1110.001", "T1110.003", "T1078"]
severity: Medium
source_doc: Brute_Force_IR_Playbook_v1
doc_type: playbook
---

## Phase: containment
### Sub: short_term
- เนื้อหา...

### Sub: evidence_preservation [T1078]
- ถ้าใส่ T-code ท้ายชื่อ Sub จะ override technique ของทั้งไฟล์เฉพาะ chunk นี้

## Phase: eradication
### Sub: process_removal
- เนื้อหา...

## Phase: recovery
### Sub: service_restoration
- เนื้อหา...
```

กติกา:

- **ต้องมี frontmatter** ไม่งั้นไฟล์ถูกข้ามพร้อม warning สีเหลือง
- `## Phase:` ต้องใช้ชื่อตรงกับ **3 ค่านี้เท่านั้น**: `containment`, `eradication`, `recovery` — ตรงกับ scope proposal §3.3 (ห้ามเพิ่ม preparation/detection/post_incident กลับมาโดยไม่คุยกับทีมก่อน — ดู HANDOFF.md §4.2) ถ้าสะกดไม่ตรง `/retrieve` จะกรองไม่เจอและคืน chunks ว่าง
- `doc_type` เป็น `playbook` (default ถ้าไม่ใส่), `defense`, หรือ `mitre` — ใช้กรองผ่าน `/retrieve`'s `doc_types` param ได้
- 1 `### Sub:` = 1 chunk
- แก้เสร็จต้องรัน `python 01_ingest.py` ใหม่ (รองรับ subfolder แล้ว ไม่ต้องย้ายไฟล์มาไว้ระดับบนสุด)

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
- Coverage tier (full / partial / none) ตาม ARCHITECTURE.md §4 ยังไม่ได้ implement เต็มรูปแบบ — ตอนนี้มีแค่ `missing_techniques` แบบ binary (แต่มี `doc_type` filter ให้ต่อยอดแล้ว)
- `POST /alerts/ingest` (webhook จริง, §3.5) กับ workflow สร้าง playbook เต็มเส้น (`n8n-workflow.json`, ยังใช้ Mock node) **ยังเป็นคนละ workflow แยกกัน** — ยังไม่เชื่อมเป็นเส้นเดียว
- `_CASES` ใน `api.py` (store ของ `/alerts/ingest`) เป็น dict ในหน่วยความจำเหมือน `_STORE` — restart แล้วหายหมด และยังไม่มี unique index กัน race condition ตอนสอง request เข้าพร้อมกัน
- `cti_verdict` เป็น `"unknown"` เสมอ — CTI enrichment (VirusTotal/AbuseIPDB) ยังไม่ implement ทำให้ NCSC category บางเคสยังไม่แม่นเท่าที่ควร (ดู HANDOFF.md §4.6)
- `account_privilege` มาจาก lookup table hardcode ใน n8n (`ACCOUNT_PRIVILEGE_LOOKUP`) — ยังไม่ได้ถาม AD group membership จริง
