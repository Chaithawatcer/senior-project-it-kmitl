"""
gen_mitre_kb.py — ดึง MITRE ATT&CK Mitigations อย่างเป็นทางการ (offline ผ่าน mitreattack-python)
เข้า KB ส่วนที่ 3 ตามขอบเขต proposal §3.2 (IR playbook เอง + defense doc รายเทคนิค + MITRE Mitigations)

ก่อนรันต้องดาวน์โหลด STIX data ก่อน (ครั้งเดียว ~50MB ไม่ต้อง commit เข้า git):
  curl -L -o mitre_data/enterprise-attack.json \
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

รัน:  python gen_mitre_kb.py
แล้วรัน 01_ingest.py ใหม่เพื่อ ingest ไฟล์ที่ได้เข้า ChromaDB (rglob ครอบ playbooks/mitre/ อยู่แล้ว)
"""

import re
from pathlib import Path

from mitreattack.stix20 import MitreAttackData

STIX_FILE = Path(__file__).parent / "mitre_data" / "enterprise-attack.json"
OUT_DIR = Path(__file__).parent / "playbooks" / "mitre"

# technique ที่ KB ปัจจุบันครอบคลุม (credential attack บน AD) — เพิ่มได้เรื่อยๆ ตาม KB ที่โต
TECHNIQUES = ["T1110", "T1110.001", "T1110.003", "T1078", "T1003.001", "T1550.002", "T1021.001"]

PHASES = ["containment", "eradication", "recovery"]

# หมายเหตุออกแบบ: MITRE Mitigations เป็นแนวป้องกันเชิงพฤติกรรม ไม่ได้ผูกกับ phase ใด phase หนึ่ง
# โดยธรรมชาติ (ต่างจาก threat playbook ที่เขียนแยกขั้นตอนตาม incident lifecycle) แต่ /retrieve
# กรอง phase แบบ exact match เสมอ (ARCHITECTURE.md §4.3) — จึงจงใจ "ซ้ำเนื้อหาเดิม" ลงทั้ง 3 phase
# เพื่อให้หา mitigation เจอได้ไม่ว่ากำลังเขียน phase ไหนอยู่ แลกกับพื้นที่เก็บที่มากขึ้น 3 เท่า
# ซึ่งถูกกว่าการเพิ่ม logic กรองแบบ phase-agnostic เข้า /retrieve ตอนนี้ — ควรทบทวนอีกทีตอนทำ
# tiering เต็มรูปแบบตาม ARCHITECTURE.md §4 (primary/secondary ตาม doc_type)


def slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text.lower()).strip("_")


def main():
    if not STIX_FILE.exists():
        print(f"❌ ไม่พบ {STIX_FILE}")
        print("ดาวน์โหลดก่อน:")
        print("  curl -L -o mitre_data/enterprise-attack.json \\")
        print("    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
        return

    print("กำลังโหลด MITRE ATT&CK STIX data (~50MB, ใช้เวลาสักครู่) ...")
    attack = MitreAttackData(str(STIX_FILE))
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    written = 0
    for tid in TECHNIQUES:
        tech = attack.get_object_by_attack_id(tid, "attack-pattern")
        if tech is None:
            print(f"⚠ ไม่พบ technique {tid} ใน STIX data — ข้าม")
            continue

        mitigations = attack.get_mitigations_mitigating_technique(tech.id)
        if not mitigations:
            print(f"⚠ {tid} ({tech.name}) ไม่มี mitigation ใน ATT&CK — ข้าม")
            continue

        lines = [
            "---",
            f'threat_name: "{tech.name}"',
            f'technique_ids: ["{tid}"]',
            "severity: Medium",
            f'source_doc: "MITRE_ATTACK_Mitigations_{tid}"',
            "doc_type: mitre",
            "---",
            "",
            f"> ที่มา: MITRE ATT&CK ({tid} — {tech.name}) ดึงผ่าน mitreattack-python (offline)",
            "> เนื้อหาด้านล่างคือคำอธิบายทางการจาก ATT&CK โดยตรง ไม่ได้เรียบเรียงใหม่",
            "> เพื่อให้อ้างอิงย้อนกลับไปยังเอกสารต้นฉบับได้ตรง",
            "",
        ]

        for phase in PHASES:
            lines.append(f"## Phase: {phase}")
            for m in mitigations:
                obj = m["object"]
                mid = attack.get_attack_id(obj.id) or "M????"
                lines.append(f"### Sub: {slug(obj.name)} [{tid}]")
                lines.append(f"**{mid} — {obj.name}**")
                lines.append("")
                lines.append(obj.description.strip())
                lines.append("")

        out_file = OUT_DIR / f"{slug(tid)}_mitigations.md"
        out_file.write_text("\n".join(lines), encoding="utf-8")
        written += 1
        print(f"✓ {tid} ({tech.name}): {len(mitigations)} mitigations -> {out_file.name}")

    print(f"\nเสร็จแล้ว — เขียน {written} ไฟล์ลง {OUT_DIR}")
    print("รัน `python 01_ingest.py` ใหม่เพื่อ ingest เข้า ChromaDB")


if __name__ == "__main__":
    main()
