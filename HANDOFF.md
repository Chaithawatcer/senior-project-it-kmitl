# HANDOFF — Omnissiah (AI-Driven SOC Copilot)

เอกสารส่งต่องาน สำหรับ **เพื่อนในทีมที่มาทำต่อ** และ **AI assistant ที่รับ context ใหม่**
อัปเดตล่าสุด: 2026-07-23 (เพิ่ม §0.1 — Central Schema + webhook จริงบนบรานช์ `reactive-pipeline-1-2-3`)

> ถ้าคุณเป็น AI assistant: อ่านไฟล์นี้ให้จบก่อนแก้โค้ด ส่วน §4 (ข้อตกลงที่ห้ามพัง) คือสิ่งที่แก้ผิดแล้วระบบพังเงียบ ๆ โดยไม่ error

---

## 0. รอบแก้ไขนี้ทำอะไรไปบ้าง (เทียบกับ commit ก่อนหน้าบนบรานช์นี้)

โค้ดฉบับก่อนหน้ามีหลายจุดที่เบี่ยงไปจากทั้ง proposal ที่เสนออาจารย์และ ARCHITECTURE.md เอง — พบระหว่างรีวิวเทียบ 3 เอกสาร (proposal / ARCHITECTURE.md / โค้ดจริง) แล้วแก้ดังนี้:

| ประเด็น | เดิม | แก้เป็น |
|---|---|---|
| จำนวน phase ของ playbook | 5 phase ตาม NIST (preparation, detection, containment, eradication, post_incident) | **3 phase ตาม proposal §3.3 และ ARCHITECTURE.md §2**: containment, eradication, recovery — เนื้อหา preparation/detection เดิมย้ายไปเป็น "เอกสารอ้างอิง" ที่หัวไฟล์ playbook แทน (ไม่ถูก ingest แต่ไม่ทิ้ง) |
| Mock alert | SSH brute force บน Linux (`web-server-01`, `/var/log/auth.log`) — ผิด scope proposal §3.1 ที่จำกัดแค่ AD/Windows Event Log | Windows AD Event 4625+4740 (`DC01`, `admin_somchai`, `185.15.58.22`) ตรง schema ที่ `Normalize Alert` เขียนไว้อ่านอยู่แล้ว (`data.win.eventdata.*`) — เดิม mock กับ normalize logic ไม่ตรงกันเอง |
| NCSC Categorisation + Escalation Matrix | ไม่มีเลย — severity เป็นแค่ Wazuh `rule.level` map ตรง ๆ | endpoint ใหม่ `POST /assess/severity` — deterministic rubric (ดู §4.6) คืน category C2–C6 + escalation tier/owner/SLA ต่อจาก `study/03`, `study/04` |
| KB (Knowledge Base) | มีแค่ `doc_type=playbook` (3 ไฟล์) — proposal §3.2 ต้องการ 3 ส่วน | เพิ่ม `doc_type` metadata + `doc_type=defense` (1 ไฟล์ตัวอย่าง) + `doc_type=mitre` (7 ไฟล์ ดึงจริงผ่าน `mitreattack-python`) → **11 ไฟล์ 147 chunks** |
| `mitreattack-python` | ไม่อยู่ใน `requirements.txt` เลย ทั้งที่ proposal ระบุชัด | เพิ่มแล้ว + สคริปต์ `gen_mitre_kb.py` รันได้จริง (ทดสอบแล้ว) |
| `pymisp`, `python-frontmatter` | อยู่ใน requirements แต่ไม่เคยถูก import | เอาออก (ตอบคำถามที่ค้างใน §7 ฉบับก่อน) |

ทุกจุดทดสอบ end-to-end แล้วด้วยการจำลอง flow ทั้งเส้นผ่าน HTTP ตรง (ไม่ผ่าน n8n เพราะไม่มี Gemini key ในเครื่องทดสอบ) — ดูผลใน §4.6 และ §4.7

---

## 0.1 บรานช์ `reactive-pipeline-1-2-3` เพิ่มอะไรต่อจาก §0

ต่อยอดจากรอบแก้ข้างบน — implement ARCHITECTURE.md §2 ขั้นที่ 1-3 ของ Pipeline 1 (เชิงรับ) แบบ**แยก
workflow ต่างหาก** ไม่ปนกับ `n8n-workflow.json` เดิม (กันของเก่าที่ทดสอบผ่านแล้วพัง):

| ไฟล์ | ทำอะไร |
|---|---|
| `Project/central_schema.py` (ใหม่) | Central Schema เต็ม: `CaseRecord`, `Timestamps` (t0-t6, เติมแค่ t0/t1), `Entities`, `compute_dedup_key()`, `normalize_alert()`, `extract_observables()` |
| `Project/api.py` (แก้) | เพิ่ม `POST /alerts/ingest` (รับ webhook จริง → normalize → dedup → extract) และ `GET /alerts/{case_id}` |
| `n8n-workflow-reactive-ingest.json` (ใหม่) | Webhook node จริง → HTTP Request → `/alerts/ingest` → Respond to Webhook |

**ทดสอบจริงผ่าน n8n ไม่ใช่แค่จำลอง:** ดาวน์โหลด/รัน n8n จริงผ่าน `npx n8n` (ไม่มี Docker ในเครื่องทดสอบ), `publish:workflow` เพื่อ activate, `n8n start` ให้ webhook ทำงานค้าง, ยิง curl เข้า `http://localhost:5678/webhook/alerts/ingest` จริงด้วย Windows AD Event 4625/4740 — ได้ `CaseRecord` กลับมาครบ (`dedup_key`, `t0_ingested`/`t1_normalized`, `entities`), ยิงซ้ำได้ `status: dedup_hit` คืน `case_id` เดิม

**ยังไม่เชื่อมกับส่วนที่เหลือ** — `/alerts/ingest` เป็น workflow แยกจาก `n8n-workflow.json` (ที่ยังใช้ Mock Wazuh Alert node เหมือนเดิม) โดยตั้งใจ เพราะ field ที่ `Assess Severity` ต้องใช้ (`account_privilege`, `attack_success`, `cti_verdict`) ยังไม่มีทางเทียบเท่าใน Central Schema ตอนนี้ — ต้องคุยกันก่อนว่าจะรวมสองเส้นยังไง

---

## 1. อ่านอะไรก่อน

| ลำดับ | ไฟล์ | ได้อะไร |
|---|---|---|
| 1 | `ARCHITECTURE.md` | สถาปัตยกรรมเป้าหมาย 6 layers, 2 pipelines — **นี่คือปลายทาง ไม่ใช่ของที่มีอยู่จริงทั้งหมด** |
| 2 | `HANDOFF.md` (ไฟล์นี้) | ของที่มีอยู่จริงตอนนี้ + เหตุผลเบื้องหลัง |
| 3 | `USAGE.md` | วิธีติดตั้งและรัน |
| 4 | `Project/central_schema.py` | Central Schema — normalize/dedup/extract observables (ใหม่ §0.1) |
| 5 | `Project/api.py` | logic หลักทั้งหมดอยู่ที่นี่ |
| 6 | `Project/01_ingest.py` | วิธี chunk เอกสารเข้า ChromaDB (รองรับ `doc_type` + subfolder แล้ว) |
| 7 | `Project/gen_mitre_kb.py` | ดึง MITRE Mitigations ทางการเข้า KB |
| 8 | `n8n-workflow.json` | orchestration เต็มเส้น 14 nodes (mock trigger → NCSC → RAG playbook) |
| 9 | `n8n-workflow-reactive-ingest.json` | webhook จริงสำหรับ Pipeline 1 ขั้น 1-3 เท่านั้น (ใหม่ §0.1) |

---

## 2. สถานะปัจจุบัน — เทียบกับ ARCHITECTURE.md

| Layer ตาม §1 | สถานะ | หมายเหตุ |
|---|---|---|
| [1] Ingestion (Pipeline 1) | 🟢 มี webhook จริงแล้ว (แยก workflow) | `n8n-workflow-reactive-ingest.json` มี Webhook node จริงเรียก `POST /alerts/ingest` — ทดสอบผ่านจริงแล้ว (§0.1) แต่ workflow สาธิตเต็มเส้น (`n8n-workflow.json`) ยังใช้ `Mock Wazuh Alert` เหมือนเดิม เพราะสองเส้นยังไม่ได้เชื่อมกัน |
| [2] Normalization | 🟢 ทำแล้ว (2 จุด) | (ก) `Normalize Alert` ใน n8n derive `account_privilege`/`distinct_accounts`/`attack_success`/`cti_verdict` ป้อน `/assess/severity` (ข) `central_schema.py` ทำ Central Schema เต็มรูปแบบ + dedup + t0/t1 ผ่าน `/alerts/ingest` — **ยังเป็นคนละ schema กัน** ยังไม่ได้รวมเป็นอันเดียว |
| [3] Enrichment & Analysis | 🟡 ครึ่งเดียว | **NCSC + Escalation Matrix ทำแล้ว** (deterministic, ดู §4.6) — **CTI enrichment (VirusTotal/AbuseIPDB) ยังไม่ทำ** `cti_verdict` เป็น `"unknown"` เสมอตอนนี้ |
| [4] RAG Core | 🟢 ทำแล้ว + ขยาย | ChromaDB + hybrid retrieval + วนทีละ phase ครบ + รองรับ filter `doc_type` แล้ว (ยังไม่ได้ทำ tiering primary/secondary เต็มรูปแบบ) |
| [5] Output & Notification | 🟡 ครึ่งเดียว | ประกอบ markdown ได้ (มี NCSC/Escalation table แล้ว) แต่ไม่มี Teams/LINE |
| [6] Human Review Gate | 🔴 ยังไม่ทำ | มีแค่ field `status: "draft"` ไม่มีกลไกอนุมัติ |
| Pipeline 2 (เชิงรุก) | 🔴 ยังไม่เริ่ม | ไม่มีโค้ดเลยสักบรรทัด — งานใหญ่สุดที่เหลือ |

**สรุป:** RAG core + NCSC/Escalation decision (ส่วนตรรกะที่เสี่ยง hallucination สูงสุด) พิสูจน์แล้วว่าใช้งานได้จริงและตรง scope proposal สิ่งที่เหลือใหญ่ที่สุด 2 อย่างคือ **CTI enrichment** (ปลดล็อก cti_verdict ที่แท้จริง) และ **Pipeline 2 ทั้งเส้น**

---

## 3. Knowledge Base ที่มีอยู่

**11 ไฟล์ · 147 chunks · ครบ 3 phase ทุกไฟล์ (containment/eradication/recovery)** — ครบ 3 ส่วนตาม proposal §3.2 แล้ว

| doc_type | ไฟล์ | threat_name / technique | ที่มา |
|---|---|---|---|
| `playbook` | `01_brute_force.md` | Brute Force — T1110.001, T1110.003, T1078 | ทีมเขียนเอง |
| `playbook` | `02_credential_dumping.md` | Credential Dumping — T1003.001, T1078, T1550.002 | ทีมเขียนเอง |
| `playbook` | `03_rdp_bruteforce.md` | RDP Brute Force — T1110.001, T1021.001, T1078 | ทีมเขียนเอง |
| `defense` | `defense/T1110_brute_force_defense.md` | เทคนิค T1110/.001/.003 ล้วน ไม่ผูก threat scenario | ทีมเขียนเอง (ตัวอย่าง — ควรเพิ่มอีกตาม technique ที่ KB ขยาย) |
| `mitre` | `mitre/t1110_mitigations.md` และอีก 6 ไฟล์ (T1110.001, T1110.003, T1078, T1003.001, T1550.002, T1021.001) | Mitigations ทางการต่อ technique | `gen_mitre_kb.py` ผ่าน `mitreattack-python` (offline, ดาวน์โหลด STIX ครั้งเดียว) |

ครอบคลุมแค่ธีม **credential attack บน Active Directory** — นอกขอบเขตนี้ระบบจะคืน `chunks: []` แล้วแปะธง ⚠️ ซึ่งเป็นพฤติกรรมที่ถูกต้อง ไม่ใช่บั๊ก

**หมายเหตุ mitre docs:** เนื้อหาเดียวกันถูก duplicate ลงทั้ง 3 phase โดยตั้งใจ (MITRE Mitigations ไม่ได้ผูก phase ใด phase หนึ่งโดยธรรมชาติ ต่าง จาก threat playbook) เหตุผลเต็มอยู่ในคอมเมนต์ท้าย `gen_mitre_kb.py` — ควรทบทวนอีกทีตอนทำ tiering เต็มรูปแบบ (§6 ข้อ 3)

**ต้องดาวน์โหลด STIX data เองก่อนรัน `gen_mitre_kb.py`** (ไม่ commit ไฟล์ ~50MB เข้า git):
```bash
mkdir -p Project/mitre_data
curl -L -o Project/mitre_data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

---

## 4. ข้อตกลงที่ห้ามพัง (invariants)

ทุกข้อนี้ถ้าแก้ผิด **ระบบจะไม่ error แต่ผลลัพธ์จะมั่ว** — อันตรายกว่าพังตรง ๆ

### 4.1 embedding model ต้องเป็นตัวเดียวกันทั้ง ingest และ query

`01_ingest.py` และ `api.py` ใช้ `embedding_functions.DefaultEmbeddingFunction()` (= `all-MiniLM-L6-v2`) เหมือนกัน
ถ้าเปลี่ยนที่ใดที่หนึ่ง vector space จะคนละชุด → retrieval คืน chunk ที่ไม่เกี่ยวเลยโดยไม่มี error
**เปลี่ยนแล้วต้องรัน `01_ingest.py` ใหม่ทุกครั้ง**

### 4.2 ชื่อ phase ต้องตรง 3 ค่านี้เป๊ะ — **เปลี่ยนจาก 5 เป็น 3 แล้ว**

`containment` · `eradication` · `recovery`

ผูกกัน 3 ที่: หัวข้อ `## Phase:` ในไฟล์ playbook → metadata ใน ChromaDB → `SECTIONS[].phase` ใน `api.py`
สะกดไม่ตรงแม้ตัวเดียว → `where={"phase": {"$eq": ...}}` กรองไม่เจอ → chunks ว่าง

> ⚠️ **ห้ามเพิ่มกลับเป็น 5 phase แบบ NIST lifecycle** โดยไม่คุยกับทีม/อาจารย์ก่อน — ขอบเขต proposal §3.3 ระบุไว้แค่ 3 phase (Containment/Eradication/Recovery) ตรงกับตัวอย่าง Quick Win ที่อาจารย์ให้มาด้วย

### 4.3 ไม่มี silent fallback — โดยตั้งใจ

`api.py`'s `/retrieve` เขียนไว้ชัด: ถ้าไม่ match technique เลย ให้คืน `chunks: []` แล้วปล่อยให้ธง ⚠️ ขึ้น
**ห้ามเติม fallback ที่คืน chunk ใกล้เคียงมาแทน** — เหตุผลคือ playbook ที่ดูสมบูรณ์แต่ไม่มีข้อมูลจริงรองรับ อันตรายกว่า playbook ที่บอกตรง ๆ ว่าไม่รู้

### 4.4 retrieval เป็น 2 ชั้นเสมอ (+ filter `doc_type` เสริมได้)

ชั้น 1 กรอง `phase` (+ `doc_type` ถ้าระบุ) ที่ ChromaDB → ชั้น 2 กรอง `technique_ids` ที่ Python (เพราะ ChromaDB ใช้ `$contains` กับ array ไม่ได้ จึงเก็บ technique เป็น comma-string แล้วกรองเอง)
ดึงมา 30 แล้วค่อยตัดเหลือ `top_k` เพราะกรองซ้ำรอบสองจะเหลือน้อยกว่าที่ขอ

### 4.5 No Auto-Remediation

ระบบไม่ส่งคำสั่งไปยังอุปกรณ์เครือข่ายทุกกรณี output เป็น Draft เสมอ
นี่คือ **คุณสมบัติของสถาปัตยกรรม ไม่ใช่ข้อจำกัด** — เป็นเหตุผลที่ระบบปลอดภัยพอจะให้ LLM เขียนขั้นตอนได้

### 4.6 NCSC + Escalation Matrix เป็น deterministic Python ไม่ใช่ LLM — ⭐ ใหม่

`POST /assess/severity` ใน `api.py` ตัดสิน category (C2–C6) + escalation tier/owner/SLA ด้วย rubric ตายตัว (ดูโค้ด + คอมเมนต์เหตุผลในไฟล์ ตรงหัวข้อ "severity (NCSC + Escalation Matrix)")

**ทำไมไม่ใช้ LLM ทั้งที่ ARCHITECTURE.md §2 ขั้นที่ 5 เขียนว่า "LLM node → Gemini API":** การตัดสิน category กระทบว่าใครถูกปลุกกลางดึกและ SLA เท่าไหร่ — เป็นจุดที่ผลกระทบของ hallucination สูงสุดในระบบ จึงเลือกให้เป็นโค้ดที่ unit test ได้แน่นอน แทนที่จะให้ LLM ตัดสินเอง ตรงกับหลักการที่ไฟล์นี้ (§4 ทั้งหมด) ยึดอยู่แล้ว **นี่คือจุดที่เบี่ยงจากถ้อยคำใน ARCHITECTURE.md — ควรคุยกับทีม/อาจารย์ว่ายอมรับไหม หรือจะปรับ ARCHITECTURE.md ให้ตรงกับของจริง**

**ข้อมูลที่ยังขาด:** `cti_verdict` เป็น `"unknown"` เสมอตอนนี้ (CTI enrichment ยังไม่ทำ) — rubric ตีความ `"unknown"` แบบระมัดระวัง (เทียบเท่า suspicious ไม่ใช่ clean) กันประเมินต่ำเกินจริง เมื่อต่อ CTI จริงแล้วต้องแทนที่ค่านี้ (`Normalize Alert` node ใน n8n)

**`account_privilege`** ตอนนี้มาจาก lookup table hardcode ใน `Normalize Alert` (`ACCOUNT_PRIVILEGE_LOOKUP`) — เป็น stand-in ชั่วคราวแทนการถาม AD group membership จริง ต้องแทนที่ก่อนขึ้นระบบจริง

### 4.7 ทดสอบแล้ว (ไม่ใช่แค่เขียนแล้วเดา)

รันจำลอง flow เต็มเส้นผ่าน HTTP ตรง (mock alert → normalize → `/assess/severity` → `/template/sections` → `/retrieve` ทั้ง 3 phase → `/playbooks/assemble` → `/playbooks` → `/playbooks/lookup`) ยืนยันว่า:
- `/assess/severity` ให้ผลตรงตามเฉลย 3 scenario (Domain Admin+สำเร็จ→C2, Domain Admin+ไม่สำเร็จ+CTI unknown→C3, Standard+clean→C6)
- `/retrieve` เจอ chunk ครบทั้ง 3 phase สำหรับ T1110.001 รวม `doc_type` ทั้ง playbook/defense/mitre และ filter `doc_types` ทำงานถูกต้อง
- markdown ที่ประกอบออกมามี Alert Context + NCSC/Escalation table + 3 phase section ครบ
- dedup lookup คืนค่า `ncsc_category`/`escalation_tier` ที่บันทึกไว้ถูกต้อง

ยังไม่ได้ทดสอบผ่าน n8n จริง (ไม่มี Gemini key ในเครื่องที่แก้ไฟล์นี้) — **ต้องรัน `Execute Workflow` ใน n8n จริงอีกรอบก่อนเชื่อว่า wiring ถูก 100%**

---

## 5. จุดที่ยังเปราะ / รู้ตัวแล้วแต่ยังไม่แก้

| จุด | รายละเอียด | ผลกระทบ |
|---|---|---|
| `_STORE` เป็น dict ใน RAM | restart แล้วหายหมด | `/playbooks/lookup` ใช้ dedup ข้ามรอบไม่ได้จริง |
| technique match ใช้ substring | `"T1110" in "T1110.001,..."` → True | parent technique match child ได้โดยบังเอิญ **แต่ทางกลับกันไม่ได้** — ถ้าเปลี่ยนเป็น exact match ต้องแก้ทั้ง KB |
| `fallback_used` hardcode `False` | field ตายอยู่ | `Aggregate Sections` อ่านค่านี้ไปแต่ได้ `false` ตลอด |
| Coverage tier (full/partial/none) ตาม ARCHITECTURE §4 ยังไม่มี | มี `doc_type` filter แล้วแต่ยังไม่ได้ใช้ตัดสิน tier, ไม่มี similarity threshold | ตอนนี้มีแค่ `missing_techniques` แบบ binary |
| `t0`/`t1` + dedup มีแล้วสำหรับ **alert ingestion** (`/alerts/ingest`, §0.1) แต่ `t2`–`t6` ยังว่างเสมอ และยังไม่เชื่อมกับ dedup ของ **playbook generation** (`/playbooks/lookup`, คนละ store กัน) | ยังวัด TTR เต็มเส้นไม่ได้ (แค่ t0-t1), race condition ตอนสอง request ยิง `/alerts/ingest` พร้อมกันยังเกิดได้ (`_CASES` เป็น dict เฉย ๆ ไม่มี unique index/lock) | ต้องรวม 2 schema เป็นอันเดียว + เพิ่ม lock ก่อนขึ้นระบบจริง |
| API key เป็น plaintext ใน `n8n-workflow.json` | ค่าปัจจุบันเป็น placeholder | **ห้าม commit key จริงลงไฟล์นี้เด็ดขาด** |
| MITRE mitigation chunk ซ้ำ 3 phase | ดู §3 หมายเหตุ | เก็บพื้นที่มากกว่าที่จำเป็น 3 เท่า — ยอมรับได้ตอนนี้ |
| `cti_verdict` เป็น `"unknown"` เสมอ | CTI enrichment ยังไม่ทำ | NCSC category ที่ต้องพึ่ง CTI (เช่น C3 ในหลายเคส) ยังไม่แม่นเท่าที่ควร |
| `account_privilege` มาจาก hardcode lookup table | ยังไม่ถาม AD จริง | ใช้ได้แค่กับ mock/demo ไม่ใช่ของจริง |

---

## 6. งานที่เหลือ — เรียงตามลำดับที่ควรทำ

1. **รวม Central Schema (`/alerts/ingest`) เข้ากับ workflow สร้าง playbook เต็มเส้น** ⭐ ใหม่ — ตอนนี้เป็น 2 workflow แยกกัน (§0.1) ต้องตัดสินใจว่า `Assess Severity` จะอ่าน field จาก `CaseRecord` โดยตรง หรือแปลง `CaseRecord` → job payload แบบเดิมก่อน
2. **CTI enrichment (VirusTotal/AbuseIPDB)** — คั่นระหว่าง `/alerts/ingest` (หรือ `Normalize Alert`) กับ `Assess Severity` แล้วแทนที่ `cti_verdict: "unknown"` ด้วยผลจริง (ดู `study/05-cti-enrichment-apis.md` มี endpoint/response format/เกณฑ์แปลงผลพร้อมใช้)
3. **Coverage tier เต็มรูปแบบ** — ใช้ `doc_type` filter ที่เพิ่งเพิ่ม + เปิด `distances` ใน `include=[...]` แล้วหา threshold จากการทดลอง **อย่าตั้งค่าลอย ๆ**
4. **Persist `_STORE` และ `_CASES`** — SQLite ก็พอ ทั้งสอง store ยังเป็น in-memory dict
5. **Notification + Review Gate** — Teams/LINE (⚠️ LINE Notify ปิดบริการแล้ว มี.ค. 2025 — ใช้ Messaging API หรือ Teams แทน) + กลไก Draft → Approved
6. **Pipeline 2 (RSS)** — งานใหญ่สุด ทำท้ายสุด ใช้ RAG core ตัวเดิมได้เลย
7. **แทน `ACCOUNT_PRIVILEGE_LOOKUP` ด้วย AD group membership query จริง** — ตอนต่อ AD จริงแล้ว

---

## 7. เรื่องที่ยังไม่ได้ตัดสินใจ (ต้องคุยกันก่อนลงมือ)

- **จะรวม `CaseRecord` (Central Schema, §0.1) กับ job payload เดิมของ `Normalize Alert` ยังไง** — ตอนนี้เป็นคนละ schema กันโดยสิ้นเชิง มีบางฟิลด์ซ้ำความหมายกัน (`threat_name`, `technique_ids`/`mitre_techniques`) ต่างชื่อกัน ต้องเลือกว่าจะยึด schema ไหนเป็นหลักก่อนเชื่อม 2 workflow
- **ARCHITECTURE.md §2 ขั้นที่ 5 เขียนว่า NCSC เป็น "LLM node" แต่ implementation จริงเป็น deterministic Python (§4.6)** — ยอมรับการเบี่ยงนี้ไหม หรือปรับถ้อยคำ ARCHITECTURE.md ให้ตรงกับของจริง
- **MITRE mitigation chunk ที่ duplicate ลง 3 phase (§3)** — ทางออกชั่วคราว ควรทำ retrieval แบบ phase-agnostic สำหรับ `doc_type=mitre` จริงจังกว่านี้ไหม
- **จะย้ายไป `google-genai` SDK ไหม** — `requirements.txt` ยังใช้ `google-generativeai` ซึ่ง Google deprecate แล้ว ตอนนี้ n8n เรียก REST ตรงจึงยังไม่กระทบ แต่ถ้าจะเขียน LLM logic ฝั่ง Python ต้องเลือก
- **logic จะอยู่ที่ n8n หรือ FastAPI ทั้งหมดไหม** — ตอนนี้ปนกัน (normalize/derive account_privilege อยู่ n8n, retrieval/assemble/severity assessment อยู่ Python) คอมเมนต์ใน `Normalize Alert` เขียนว่า "ตอนขึ้นจริง FastAPI จะเป็นคนทำขั้นนี้" — ยังไม่ได้ย้าย
- **จะรองรับ MITRE technique ระดับ parent หรือ sub เท่านั้น** — เกี่ยวกับ §5 เรื่อง substring match

---

## 8. ค่าที่ต้องตั้งเองก่อนรัน

| ค่า | ตั้งที่ไหน | ค่า placeholder ปัจจุบัน |
|---|---|---|
| `OMNISSIAH_API_KEY` | env บนเครื่อง + header `X-API-Key` ใน `n8n-workflow.json` 5 nodes + `n8n-workflow-reactive-ingest.json` 1 node (`Ingest Alert`) | `REPLACE_WITH_SHARED_SECRET` |
| Gemini API key | header `x-goog-api-key` ใน node `Gemini Generate` (มีแค่ใน `n8n-workflow.json`) | `Gemini-API` |
| Base URL ของ API | 5 HTTP Request nodes ใน `n8n-workflow.json` + 1 ใน `n8n-workflow-reactive-ingest.json` | `http://host.docker.internal:8000` (สมมติว่า n8n อยู่ใน Docker) |

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
| Escalation SLA (C2–C6) | 15 / 30 / 60 / 240 / 1440 นาที | ค่าตั้งต้นจาก `study/04` — ยังไม่ยืนยันกับอาจารย์ |
