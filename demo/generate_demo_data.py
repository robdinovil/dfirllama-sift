#!/usr/bin/env python3
"""
generate_demo_data.py
=====================
Genera el dataset sintético de demostración para DFIRLlama-SIFT.

Escenario: servidor RDP comprometido durante 6 meses.
  - Usuarios legítimos conectándose desde red interna (10.x.x.x)
  - A partir del 2024-06-19: Lumma Stealer via ClickFix (usuario jparker)
  - A partir del 2024-06-22: atacante desde IP externa (102.20.90.8, Africa)
  - 2024-06-22 19:45: log clearing (EventId 1102)
  - Dataset final: 1,800 eventos RDP (EventId 21/22/23/24)

Los datos son completamente sintéticos — no provienen de ningún curso
ni material propietario. El escenario es representativo de un incidente
real de RDP compromise.

Uso:
    python3 demo/generate_demo_data.py
    python3 demo/generate_demo_data.py --output /ruta/custom.db
"""

import argparse
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


USERS = ["administrator", "jparker", "mshelly", "itsupport", "svcbackup", "dbadmin"]
ADMIN_IP = "10.0.0.1"          # el admin SIEMPRE usa esta IP interna
INTERNAL_IPS = ["10.0.0.5", "10.0.1.10", "10.0.2.20", "10.0.3.50"]
EXTERNAL_LEGIT = ["53.58.75.69", "185.220.101.34"]
ATTACKER_IP = "102.20.90.8"    # SOLO el atacante usa esta IP
SERVER = "acme-rds01.acmecorp.local"
CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

EVENT_DESCRIPTIONS = {
    21: "Remote Desktop Services: Session logon succeeded",
    22: "Remote Desktop Services: Shell start notification received",
    23: "Remote Desktop Services: Session logoff succeeded",
    24: "Remote Desktop Services: Session has been disconnected",
}

START_DATE = datetime(2024, 1, 1, tzinfo=timezone.utc)
END_DATE   = datetime(2024, 6, 28, 23, 59, 59, tzinfo=timezone.utc)
COMPROMISE_DATE = datetime(2024, 6, 22, 19, 41, tzinfo=timezone.utc)
LOG_CLEAR_DATE  = datetime(2024, 6, 22, 19, 45, 33, tzinfo=timezone.utc)


def rand_ts(start: datetime, end: datetime) -> str:
    delta   = (end - start).total_seconds()
    offset  = random.uniform(0, delta)
    ts      = start + timedelta(seconds=offset)
    micro   = random.randint(0, 999999)
    return ts.strftime(f"%Y-%m-%d %H:%M:%S.{micro:06d}")


def make_session(ts_base: str, user: str, ip: str,
                 record_start: int) -> list[dict]:
    """Genera los 4 eventos de una sesión RDP completa."""
    dt = datetime.strptime(ts_base[:26], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    rows = []
    for i, eid in enumerate([21, 22, 23, 24]):
        offset = timedelta(seconds=random.randint(i * 2, i * 60 + 30))
        ts = (dt + offset).strftime("%Y-%m-%d %H:%M:%S.%f")
        rows.append({
            "RecordNumber": record_start + i,
            "TimeCreated": ts,
            "EventId": eid,
            "MapDescription": EVENT_DESCRIPTIONS[eid],
            "UserName": user,
            "RemoteHost": ip,
            "Computer": SERVER,
            "Level": "Info",
            "PayloadData1": f"Session ID: {random.randint(1,9)}",
            "Channel": CHANNEL,
        })
    return rows


def generate(output_path: str = "demo/data/tslsm_demo.db", seed: int = 42):
    random.seed(seed)
    rows = []
    record_num = 1

    normal_end = datetime(2024, 6, 18, tzinfo=timezone.utc)

    # ── Fase 1: actividad normal ───────────────────────────────────────────────
    # Regla: administrator SIEMPRE desde ADMIN_IP (10.0.0.1)
    #        otros usuarios desde IPs internas, 5% externas legítimas
    non_admin_users = [u for u in USERS if u != "administrator"]
    for _ in range(318):  # 318 × 4 = 1272 eventos
        user = random.choices(
            ["administrator"] + non_admin_users,
            weights=[30, 20, 15, 15, 10, 10]
        )[0]
        if user == "administrator":
            ip = ADMIN_IP
        elif random.random() < 0.05:
            ip = random.choice(EXTERNAL_LEGIT)
        else:
            ip = random.choice(INTERNAL_IPS)
        ts = rand_ts(START_DATE, normal_end)
        rows.extend(make_session(ts, user, ip, record_num))
        record_num += 4

    # ── Fase 2: ataque (jun 22–28, 12 sesiones del atacante) ──────────────────
    # Atacante: 102.20.90.8 con cuenta administrator
    # Admin legítimo: sigue en 10.0.0.1 los mismos días → HALLAZGO CLAVE
    attack_sessions = [
        (0, 19, 41), (0, 22, 15), (1, 20, 30),
        (2, 23, 10), (3, 19, 55), (4, 21, 40),
        (5, 20, 05), (5, 23, 30), (6, 22, 00),
        (6, 20, 15), (7, 19, 50), (7, 21, 05),
    ]
    legit_sessions = [
        (0, 9, 30), (1, 10, 15), (2, 14, 00),
        (3, 9, 45), (4, 11, 20), (5, 10, 05),
        (6, 9, 15), (7, 10, 30),
    ]
    for day_off, h, m in attack_sessions:
        dt = COMPROMISE_DATE.replace(hour=h, minute=m, second=0) + timedelta(days=day_off)
        ts = dt.strftime("%Y-%m-%d %H:%M:%S.000000")
        rows.extend(make_session(ts, "administrator", ATTACKER_IP, record_num))
        record_num += 4

    for day_off, h, m in legit_sessions:
        dt = COMPROMISE_DATE.replace(hour=h, minute=m, second=0) + timedelta(days=day_off)
        ts = dt.strftime("%Y-%m-%d %H:%M:%S.000000")
        rows.extend(make_session(ts, "administrator", ADMIN_IP, record_num))
        record_num += 4

    # ── Padding hasta 1800 (solo usuarios no-admin) ───────────────────────────
    while len(rows) < 1800:
        user = random.choice(non_admin_users)
        ip   = random.choice(INTERNAL_IPS)
        ts   = rand_ts(START_DATE, normal_end)
        rows.extend(make_session(ts, user, ip, record_num))
        record_num += 4
    rows = rows[:1800]

    # Ordenar por tiempo
    rows.sort(key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows, 1):
        r["RecordNumber"] = i

    # ── Escribir SQLite ───────────────────────────────────────────────────────
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(output_path)
    conn.execute("DROP TABLE IF EXISTS rdp_activity")
    conn.execute("""
        CREATE TABLE rdp_activity (
            RecordNumber  INTEGER,
            TimeCreated   TEXT,
            EventId       INTEGER,
            MapDescription TEXT,
            UserName      TEXT,
            RemoteHost    TEXT,
            Computer      TEXT,
            Level         TEXT,
            PayloadData1  TEXT,
            Channel       TEXT
        )
    """)
    conn.executemany(
        "INSERT INTO rdp_activity VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(r["RecordNumber"], r["TimeCreated"], r["EventId"],
          r["MapDescription"], r["UserName"], r["RemoteHost"],
          r["Computer"], r["Level"], r["PayloadData1"], r["Channel"])
         for r in rows]
    )
    conn.commit()
    conn.close()

    print(f"✓ Dataset sintético generado: {output_path}")
    print(f"  Eventos: {len(rows)}")
    print(f"  Período: {rows[0]['TimeCreated'][:10]} → {rows[-1]['TimeCreated'][:10]}")
    attacker_rows = [r for r in rows if r["RemoteHost"] == ATTACKER_IP and r["EventId"] == 21]
    print(f"  Sesiones del atacante ({ATTACKER_IP}): {len(attacker_rows)}")
    external = [r for r in rows if not r["RemoteHost"].startswith("10.") and r["EventId"] == 21]
    print(f"  Logons externos totales: {len(external)}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Genera dataset de demo sintético")
    p.add_argument("--output", default="demo/data/tslsm_demo.db")
    p.add_argument("--seed",   type=int, default=42)
    args = p.parse_args()
    generate(args.output, args.seed)
