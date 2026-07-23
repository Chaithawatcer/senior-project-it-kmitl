# HANDOFF — Omnissiah (AI-Driven SOC Copilot)

เอกสารส่งต่องาน สำหรับ **เพื่อนในทีมที่มาทำต่อ** และ **AI assistant ที่รับ context ใหม่**
อัปเดตล่าสุด: 2026-07-24 (เพิ่ม §0.3 — Pipeline 2 เชิงรุก ขั้น 1-3 + Notification messages บนบรานช์ `proactive-pipeline-1-2-3`)

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

> ✅ **ประเด็น "จะรวมสองเส้นยังไง" ถูกตัดสินใจและทำเสร็จแล้ว — ดู §0.2 ถัดไป**

---

## 0.2 รอบล่าสุด — รวมสองเส้นเป็นเส้นเดียว + CTI Enrichment จริง + ทดสอบจบเส้นผ่าน n8n จริงสำเร็จ ⭐

### (ก) รวม Central Schema เข้า workflow หลัก

- ลบ node `Normalize Alert` (Code node ที่ฝัง logic ไว้ใน n8n) ออกจาก `n8n-workflow.json` → แทนด้วย node ใหม่ `Ingest Alert` (HTTP Request → `POST /alerts/ingest`)
- logic ที่เคยอยู่ใน Code node (`ACCOUNT_PRIVILEGE_LOOKUP`, `severity_map`) ย้ายไปอยู่ `central_schema.py` แล้ว — ตรงหลัก "logic อยู่ FastAPI, n8n แค่ orchestrate"
- `CaseRecord` ขยายให้มีทุก field ที่ node ปลายทางต้องใช้ (`severity`, `account_privilege`, `attack_success`, `distinct_accounts`, `cti_verdict`, `alert` dict สำหรับ Build Prompt/Assemble) — **ตอบคำถามค้างใน §7 ข้อแรกแล้ว: ยึด `CaseRecord` เป็น schema หลักตัวเดียว**
- node ปลายทางทั้งหมด (`Assess Severity`, `Retrieve Chunks`, `Build Prompt`, `Aggregate Sections`, `Save Draft`) rewire ให้อ่านจาก `$('Ingest Alert').first().json.case.*`
- `Mock Wazuh Alert` ยังอยู่ แต่ตอนนี้ทำหน้าที่แค่เป็นแหล่งข้อมูล mock ที่ป้อนเข้า `/alerts/ingest` — สลับเป็น Webhook จริง (แบบ `n8n-workflow-reactive-ingest.json`) ได้ทันทีโดยไม่ต้องแก้ node อื่น

### (ข) CTI Enrichment จริง (VirusTotal + AbuseIPDB) — งานค้าง §6 ข้อ 2 เสร็จแล้ว

- endpoint ใหม่ `POST /cti/enrich` ใน `api.py` (ใช้ stdlib `urllib` — ไม่เพิ่ม dependency)
- เกณฑ์ verdict: **malicious** ถ้า VT malicious ≥ 5 engine หรือ AbuseIPDB score ≥ 75 · **suspicious** ถ้า VT 1-4 หรือ score 25-74 หรือ isTor · **clean** นอกนั้น · **unknown** ถ้าเป็น private IP / ไม่มี IP / ไม่ได้ตั้ง key
- API key อ่านจาก env `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` เท่านั้น — **ไม่มี key ในไฟล์ใด ๆ ใน git**
- node ใหม่ `CTI Enrichment` คั่นระหว่าง `Ingest Alert` → `Assess Severity` — `cti_verdict` **ไม่ใช่ `"unknown"` ตายตัวอีกต่อไป** rubric NCSC ได้ค่าจริงแล้ว
- `Assemble Playbook` แสดงตาราง CTI Enrichment (IP / verdict / VT malicious / AbuseIPDB score) ในหัว playbook

### (ค) ทดสอบ end-to-end ผ่าน n8n จริง (Docker) สำเร็จ

- **ทุก node เขียว จบที่ `Save Draft` ได้ playbook สมบูรณ์**: Alert Context + ตาราง CTI + ตาราง NCSC/Escalation + 3 phase ครบไม่มีตัดกลางประโยค
- เคสทดสอบจริง: mock alert (`admin_somchai` / `185.15.58.22` / T1110.001) → CTI=**clean** (IP นี้ของ Wikimedia จริง ๆ), NCSC=**C6**, Escalation=Tier 1 / SLA 1440 นาที
- ทดสอบเพิ่มด้วย Tor exit node (`185.220.101.45`) → CTI=**malicious** (VT=16, AbuseIPDB=100/isTor) และ NCSC ขยับเป็น **C3** — พิสูจน์ว่า verdict จาก CTI มีผลต่อ rubric จริง ไม่ใช่แค่โชว์
- แก้บั๊กระหว่างทาง: `maxOutputTokens` ของ `Gemini Generate` ปรับ **2048 → 4096** (เดิม Phase 1 Containment โดนตัดกลางประโยค)

**workflow หลักตอนนี้ = 15 node:**
```
Manual Trigger → Mock Wazuh Alert → Ingest Alert → CTI Enrichment → Assess Severity
  → Get Sections → Split Out Sections
  → [วนทีละ phase] Retrieve Chunks → Rate Guard → Build Prompt → Gemini Generate → Extract Section
  → Aggregate Sections → Assemble Playbook → Save Draft
```

---

## 0.3 บรานช์ `proactive-pipeline-1-2-3` — Pipeline 2 (เชิงรุก) ขั้น 1-3 + Notification messages ⭐ ล่าสุด

implement ARCHITECTURE.md §3 ขั้นที่ 1-3 ของ Pipeline 2 ด้วย **mock data** + ต่อท้ายด้วย flow ปลายเส้น:
playbook → **ข้อความแจ้งผู้บริหาร + ข้อความแจ้งฝ่ายไอที** (ARCHITECTURE.md §5) — ทดสอบจบเส้นผ่าน HTTP จริงแล้ว

| ไฟล์ | ทำอะไร |
|---|---|
| `Project/central_schema.py` (ขยาย) | `IntelRecord` + `build_intel_record()`: normalize ข่าว → dedup **ข้ามแหล่งข่าว** (hash จากชุด CVE → technique → title ตามลำดับ) + t0/t1 + `extract_intel_iocs()` (IP/hash/domain/CVE/technique, refang defanged text ก่อน) + `extract_intel_facts()` (ประโยค **verbatim** จากต้นฉบับที่มี IoC — เป็น substring ตรง ไม่มีทาง hallucinate) |
| `Project/api.py` (ขยาย) | `POST /intel/ingest` + `GET /intel/{id}` (store `_INTEL`), `GET /template/sections?pipeline=proactive` (3 sections เชิงป้องกัน — ใช้ `phase` เดิม 3 ค่าเพื่อไม่แตะ KB metadata), `POST /playbooks/assemble` รองรับ `playbook_type/intel_source/iocs` (ได้ IoC table **defanged**), `POST /notify/messages` (2 ข้อความ, deterministic template) |
| `n8n-workflow-proactive.json` (ใหม่) | 17 node: Mock CTI Feed (ข่าว 2 ชิ้น "เรื่องเดียวกันคนละสำนัก" demo dedup) → Ingest Intel → Filter created → Limit 1 → RAG loop (doc_types defense+mitre) → Assemble → Save → Notify Messages → Prepare Notifications |

**การตัดสินใจสำคัญที่ต้องรู้:**
- **ขั้นที่ 3 (สกัด facts/IoCs) ใช้ regex + sentence matching แทน "LLM node" ที่ ARCHITECTURE.md เขียน** — เหตุผลเดียวกับ NCSC (§4.6): facts ที่เป็น substring ตรงจากต้นฉบับ = verbatim โดยโครงสร้าง ส่วน technique เอาเฉพาะ T-code ที่ปรากฏในข่าวตรง ๆ (CISA advisory มีให้เสมอ) — **ขั้นที่ 4 ของ ARCHITECTURE.md (LLM map พฤติกรรม→technique) ยังไม่ทำ** ข่าวที่ไม่เขียน T-code จะได้ techniques ว่าง
- **dedup ข้ามแหล่งข่าว hash จากชุด CVE เป็นหลัก** — heuristic หยาบ (คนละแคมเปญที่อ้าง CVE เดียวกันจะชนกัน) ต้องรีวิวตอนต่อ feed จริง
- **ข้อความแจ้งเตือนเป็น deterministic template ไม่ใช่ LLM** — ข้อความที่คนอ่านแล้วตัดสินใจ ห้ามมีโอกาส hallucinate; ผู้บริหารไม่มีศัพท์เทคนิค/IoC เลย ฝ่ายไอทีได้ IoC แบบ defanged + ขั้นตอนถัดไป
- **ยังไม่ส่งเข้า Teams/LINE จริง** — `/notify/messages` คืนตัวข้อความพร้อมส่ง ต่อ channel node ได้เลยโดยไม่แก้ logic

**ทดสอบแล้ว (HTTP ตรง ทุก assert ผ่าน):** ingest ข่าว Hacker News → `created` สกัด IoC ครบ (2 IP defanged→refang, 1 SHA256, 1 domain, CVE-2025-21298, 3 techniques) + facts 3 ประโยค verbatim ทั้งหมด → ยิงข่าว CISA เรื่องเดียวกัน → `dedup_hit` → retrieve เจอ 5 chunks ทุก phase (เฉพาะ defense/mitre) → assemble ได้ Proactive Defense Playbook + IoC table defanged → notify ได้ 2 ข้อความถูกต้อง — **ยังไม่ได้รันผ่าน n8n UI จริง** (ต้อง import + ใส่ Gemini key แล้วกด Execute — ดู USAGE.md §3.6)

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
| 8 | `n8n-workflow.json` | orchestration เต็มเส้น 15 nodes (mock trigger → ingest → CTI → NCSC → RAG playbook) |
| 9 | `n8n-workflow-reactive-ingest.json` | webhook จริงสำหรับ Pipeline 1 ขั้น 1-3 เท่านั้น (ใหม่ §0.1) |
| 10 | `n8n-workflow-proactive.json` | Pipeline 2 เชิงรุกเต็มเส้น 17 nodes (mock feed → dedup → RAG → notify) (ใหม่ §0.3) |

---

## 2. สถานะปัจจุบัน — เทียบกับ ARCHITECTURE.md

| Layer ตาม §1 | สถานะ | หมายเหตุ |
|---|---|---|
| [1] Ingestion (Pipeline 1) | 🟢 ทำแล้ว + รวมเส้นแล้ว | `n8n-workflow.json` ใช้ `Ingest Alert` → `POST /alerts/ingest` แล้ว (§0.2) — `Mock Wazuh Alert` เหลือแค่เป็นแหล่งข้อมูล mock ป้อนเข้าท่อ สลับเป็น Webhook จริงได้ทันที (`n8n-workflow-reactive-ingest.json` เป็นตัวอย่าง) |
| [2] Normalization | 🟢 ทำแล้ว (schema เดียว) | `central_schema.py` เป็น Central Schema หลักตัวเดียว — normalize + dedup + t0/t1 + derive `account_privilege`/`severity` ครบ (`Normalize Alert` Code node เดิมถูกถอดออกแล้ว, §0.2) |
| [3] Enrichment & Analysis | 🟢 ทำแล้ว | **NCSC + Escalation Matrix** (deterministic, ดู §4.6) + **CTI Enrichment จริง** (VirusTotal/AbuseIPDB ผ่าน `/cti/enrich`, §0.2) — `cti_verdict` เป็นค่าจริงแล้ว |
| [4] RAG Core | 🟢 ทำแล้ว + ขยาย | ChromaDB + hybrid retrieval + วนทีละ phase ครบ + รองรับ filter `doc_type` แล้ว (ยังไม่ได้ทำ tiering primary/secondary เต็มรูปแบบ) |
| [5] Output & Notification | 🟡 เกือบครบ | ประกอบ markdown ได้ (CTI + NCSC/Escalation + IoC table) + **ข้อความแจ้งผู้บริหาร/ฝ่ายไอทีแล้ว** (`/notify/messages`, §0.3) — เหลือแค่ต่อ channel จริง (Teams/LINE) |
| [6] Human Review Gate | 🔴 ยังไม่ทำ | มีแค่ field `status: "draft"` ไม่มีกลไกอนุมัติ |
| Pipeline 2 (เชิงรุก) | 🟡 ขั้น 1-3 + ปลายเส้นแล้ว | mock feed → IntelRecord + dedup ข้ามแหล่งข่าว + facts/IoCs → RAG (defense+mitre) → Proactive Playbook + notify (§0.3) — เหลือ: RSS/Schedule จริง, LLM technique mapping (ขั้น 4), coverage tier (ขั้น 5) |

**สรุป:** Pipeline 1 (เชิงรับ) ทำงานครบเส้นตั้งแต่รับ alert → normalize → CTI → NCSC → RAG → playbook draft และ**ทดสอบจบเส้นผ่าน n8n จริงสำเร็จแล้ว** (§0.2) สิ่งที่เหลือใหญ่ที่สุด 2 อย่างคือ **Notification + Human Review Gate** และ **Pipeline 2 ทั้งเส้น**

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

**`cti_verdict` เป็นค่าจริงแล้ว** (§0.2) — มาจาก `/cti/enrich` (VirusTotal + AbuseIPDB) ผ่าน node `CTI Enrichment` ก่อนเข้า `Assess Severity` — rubric ยังตีความ `"unknown"` แบบระมัดระวัง (เทียบเท่า suspicious ไม่ใช่ clean) สำหรับกรณี private IP / key ไม่ได้ตั้ง

**⚠️ ที่มาของ rubric:** ชื่อระดับ C1–C6 ยืมมาจากกรอบทางการของ NCSC (https://www.ncsc.gov.uk/information/categorising-uk-cyber-incidents ซึ่งออกแบบไว้ตัดสิน**ระดับประเทศ**) แต่**ตรรกะการตัดสินระดับ alert เดียวในองค์กรเป็นสิ่งที่ทีมออกแบบเองทั้งหมด** ไม่มีมาตรฐานสากลรองรับ — เวลาเขียนเล่ม/ตอบกรรมการห้ามพูดว่า "ตามมาตรฐาน NCSC" เฉย ๆ ต้องอธิบายส่วนที่ทีมออกแบบเองให้ชัด

**`account_privilege`** ตอนนี้มาจาก lookup table hardcode (`ACCOUNT_PRIVILEGE_LOOKUP` ใน `central_schema.py` — ย้ายมาจาก n8n Code node แล้ว) — เป็น stand-in ชั่วคราวแทนการถาม AD group membership จริง ต้องแทนที่ก่อนขึ้นระบบจริง

### 4.7 ทดสอบแล้ว (ไม่ใช่แค่เขียนแล้วเดา)

รันจำลอง flow เต็มเส้นผ่าน HTTP ตรง (mock alert → normalize → `/assess/severity` → `/template/sections` → `/retrieve` ทั้ง 3 phase → `/playbooks/assemble` → `/playbooks` → `/playbooks/lookup`) ยืนยันว่า:
- `/assess/severity` ให้ผลตรงตามเฉลย 3 scenario (Domain Admin+สำเร็จ→C2, Domain Admin+ไม่สำเร็จ+CTI unknown→C3, Standard+clean→C6)
- `/retrieve` เจอ chunk ครบทั้ง 3 phase สำหรับ T1110.001 รวม `doc_type` ทั้ง playbook/defense/mitre และ filter `doc_types` ทำงานถูกต้อง
- markdown ที่ประกอบออกมามี Alert Context + NCSC/Escalation table + 3 phase section ครบ
- dedup lookup คืนค่า `ncsc_category`/`escalation_tier` ที่บันทึกไว้ถูกต้อง

> ✅ **อัปเดต (§0.2): ทดสอบผ่าน n8n จริง (Docker) จบเส้นสำเร็จแล้ว** — ทุก node เขียว ได้ playbook สมบูรณ์ครบทุกส่วน wiring ยืนยันแล้ว 100% (รวมเคส CTI clean และ malicious)

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
| CTI enrichment เรียก API ภายนอกแบบ sync | `/cti/enrich` ยิง VirusTotal + AbuseIPDB ตรง ๆ (timeout 10s/ตัว) — ถ้า API ล่ม/ช้า จะหน่วงทั้ง workflow, free tier มี rate limit (VT: 4 req/นาที) | demo ถี่ ๆ อาจโดน 429 — node ตั้ง retry 3 ครั้งไว้แล้วแต่ควรรู้ไว้ |
| `account_privilege` มาจาก hardcode lookup table | ยังไม่ถาม AD จริง (`ACCOUNT_PRIVILEGE_LOOKUP` ใน `central_schema.py`) | ใช้ได้แค่กับ mock/demo ไม่ใช่ของจริง |

---

## 6. งานที่เหลือ — เรียงตามลำดับที่ควรทำ

1. ~~รวม Central Schema เข้ากับ workflow สร้าง playbook เต็มเส้น~~ ✅ **เสร็จแล้ว (§0.2 ก)**
2. ~~CTI enrichment (VirusTotal/AbuseIPDB)~~ ✅ **เสร็จแล้ว (§0.2 ข)**
3. ~~Pipeline 2 ขั้น 1-3 + ปลายเส้น playbook/notification (mock)~~ ✅ **เสร็จแล้ว (§0.3)**
4. **รัน `n8n-workflow-proactive.json` ผ่าน n8n UI จริง 1 รอบ** — logic ทดสอบผ่าน HTTP หมดแล้ว เหลือยืนยัน wiring ใน n8n (import + ใส่ key + Execute ตาม USAGE.md §3.6)
5. **Pipeline 2 ให้เป็นของจริง** — แทน Mock CTI Feed ด้วย Schedule Trigger + RSS Read, ขั้น 4 (LLM map พฤติกรรม→technique สำหรับข่าวที่ไม่เขียน T-code), ขั้น 5 (coverage tier full/partial/none)
6. **Notification channel + Review Gate** — ต่อ `/notify/messages` เข้า Teams/LINE จริง (⚠️ LINE Notify ปิดบริการแล้ว มี.ค. 2025 — ใช้ Messaging API หรือ Teams แทน) + กลไก Draft → Approved
7. **Coverage tier เต็มรูปแบบ** — ใช้ `doc_type` filter ที่เพิ่มไว้ + เปิด `distances` ใน `include=[...]` แล้วหา threshold จากการทดลอง **อย่าตั้งค่าลอย ๆ**
8. **Persist `_STORE` / `_CASES` / `_INTEL`** — SQLite ก็พอ ทั้งสาม store ยังเป็น in-memory dict + ควรรวม dedup หลายชั้นเป็นระบบเดียว (§5)
9. **แทน `ACCOUNT_PRIVILEGE_LOOKUP` ด้วย AD group membership query จริง** — ตอนต่อ AD จริงแล้ว

---

## 7. เรื่องที่ยังไม่ได้ตัดสินใจ (ต้องคุยกันก่อนลงมือ)

- ~~จะรวม `CaseRecord` กับ job payload เดิมของ `Normalize Alert` ยังไง~~ ✅ **ตัดสินใจแล้ว (§0.2 ก): ยึด `CaseRecord` เป็น schema หลักตัวเดียว, `Normalize Alert` ถูกถอดออก**
- **rubric NCSC ไม่ใช่มาตรฐานทางการ (§4.6)** — ยืมแค่ชื่อระดับ C1-C6 มา ตรรกะตัดสินทีมออกแบบเอง ต้องตกลงกันว่าจะเขียนเล่ม/นำเสนอเรื่องนี้ยังไง + เคสตัวอย่างที่ยังไม่ได้ตัดสิน: alert ใส่ Domain Admin แต่ CTI clean + ยังไม่สำเร็จ → ตอนนี้ได้ **C6 (ต่ำสุด)** เพราะ rubric ต้องมีหลักฐานสนับสนุนอย่างน้อย 1 อย่างถึงเลื่อนระดับ — ถ้าทีมเห็นว่า "เป็น Domain Admin ก็ควรได้สูงกว่า C6" ต้องแก้ if/elif ใน `assess_severity()`
- **ARCHITECTURE.md §2 ขั้นที่ 5 เขียนว่า NCSC เป็น "LLM node" แต่ implementation จริงเป็น deterministic Python (§4.6)** — ยอมรับการเบี่ยงนี้ไหม หรือปรับถ้อยคำ ARCHITECTURE.md ให้ตรงกับของจริง
- **MITRE mitigation chunk ที่ duplicate ลง 3 phase (§3)** — ทางออกชั่วคราว ควรทำ retrieval แบบ phase-agnostic สำหรับ `doc_type=mitre` จริงจังกว่านี้ไหม
- **จะย้ายไป `google-genai` SDK ไหม** — `requirements.txt` ยังใช้ `google-generativeai` ซึ่ง Google deprecate แล้ว ตอนนี้ n8n เรียก REST ตรงจึงยังไม่กระทบ แต่ถ้าจะเขียน LLM logic ฝั่ง Python ต้องเลือก
- ~~logic จะอยู่ที่ n8n หรือ FastAPI ทั้งหมดไหม~~ ✅ **แก้แล้ว (§0.2 ก): logic ทั้งหมดอยู่ FastAPI/`central_schema.py` แล้ว — n8n เหลือแค่ orchestrate + Code node เล็ก ๆ (Build Prompt/Extract/Aggregate) ที่เป็นการจัดรูป payload ไม่ใช่ business logic**
- **จะรองรับ MITRE technique ระดับ parent หรือ sub เท่านั้น** — เกี่ยวกับ §5 เรื่อง substring match

---

## 8. ค่าที่ต้องตั้งเองก่อนรัน

| ค่า | ตั้งที่ไหน | ค่า placeholder ปัจจุบัน |
|---|---|---|
| `OMNISSIAH_API_KEY` | env บนเครื่อง + header `X-API-Key` ใน `n8n-workflow.json` **7 nodes** (`Ingest Alert`, `CTI Enrichment`, `Assess Severity`, `Get Sections`, `Retrieve Chunks`, `Assemble Playbook`, `Save Draft`) + `n8n-workflow-proactive.json` **6 nodes** (`Ingest Intel`, `Get Sections`, `Retrieve Chunks`, `Assemble Playbook`, `Save Draft`, `Notify Messages`) + `n8n-workflow-reactive-ingest.json` 1 node | `REPLACE_WITH_SHARED_SECRET` |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` | env บนเครื่องที่รัน uvicorn เท่านั้น (api.py อ่านผ่าน `os.getenv`) — ไม่ตั้งก็รันได้ แต่ CTI จะคืน `unknown` | (ว่าง) |
| Gemini API key | header `x-goog-api-key` ใน node `Gemini Generate` (มีทั้งใน `n8n-workflow.json` และ `n8n-workflow-proactive.json`) — ⚠️ **คนละ header name กับ node อื่น ห้าม copy ไปวางที่ node อื่น** | `Gemini-API` |
| Base URL ของ API | 7 HTTP Request nodes ใน `n8n-workflow.json` + 6 ใน `n8n-workflow-proactive.json` + 1 ใน `n8n-workflow-reactive-ingest.json` | `http://host.docker.internal:8000` (สมมติว่า n8n อยู่ใน Docker) |

รายละเอียดวิธีตั้งอยู่ใน `USAGE.md` §2–§4

---

## 9. พารามิเตอร์ที่ตั้งไว้ตอนนี้

| ค่า | ตั้งเป็น | ที่มา |
|---|---|---|
| LLM model | `gemini-flash-lite-latest` | node `Gemini Generate` |
| temperature | `0.2` | ต่ำ เพราะต้องการความสม่ำเสมอมากกว่าความสร้างสรรค์ |
| maxOutputTokens | `4096` | ต่อ 1 phase — เดิม 2048 ทำให้ Phase 1 โดนตัดกลางประโยค ปรับแล้ว (§0.2 ค) |
| CTI verdict thresholds | malicious: VT≥5 หรือ Abuse≥75 · suspicious: VT 1-4 หรือ Abuse 25-74 หรือ isTor | ค่าตั้งต้นจาก `study/05` — ยังไม่ยืนยันกับอาจารย์ |
| `n_results` ที่ Chroma | `30` | ดึงเผื่อกรองรอบสอง |
| `top_k` ที่ส่งให้ LLM | `5` | |
| Rate Guard | หน่วง `2` วินาที | กัน Gemini 429 |
| chunk strategy | 1 `### Sub:` = 1 chunk | ไม่ได้ตัดตามจำนวน token |
| distance metric | `cosine` (`hnsw:space`) | |
| Escalation SLA (C2–C6) | 15 / 30 / 60 / 240 / 1440 นาที | ค่าตั้งต้นจาก `study/04` — ยังไม่ยืนยันกับอาจารย์ |
