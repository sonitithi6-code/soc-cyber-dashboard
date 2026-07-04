"""
Runs once a day (via GitHub Actions) to append a fresh batch of simulated
threat telemetry to cyber_security.db, so the public dashboard always has
new data even when the local security_agent.py isn't running.

If you'd rather feed the dashboard with REAL data from your own machine,
just keep running security_agent.py locally and periodically overwrite/sync
cyber_security.db in this repo (see README.md for options).
"""
import sqlite3
import random
from datetime import datetime, timedelta

DB_FILE = "cyber_security.db"

THREAT_TYPES = {
    "policy_violation": ["Banned application: notepad.exe", "Banned application: wireshark.exe",
                          "Banned application: nmap", "Banned application: calc.exe"],
    "integrity_violation": ["File Created/Dropped -> 'config.sys'", "File Modified/Tampered -> 'hosts'",
                             "File Deleted -> 'backup.zip'"],
    "physical_event": ["New external drive hardware mounted at device port 'E:'",
                        "New external drive hardware mounted at device port '/dev/sdb1'"],
    "network_anomaly": ["Unusual outbound connection to unknown IP", "Repeated failed login attempts detected"],
}


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT,
            description TEXT,
            severity INTEGER
        )
    ''')
    conn.commit()
    conn.close()


def generate_daily_batch(n_events=15):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    now = datetime.now()
    for _ in range(n_events):
        threat_type = random.choice(list(THREAT_TYPES.keys()))
        description = random.choice(THREAT_TYPES[threat_type])
        severity = random.randint(1, 10)
        # Spread events across the last 24 hours for a realistic timeline
        ts = now - timedelta(minutes=random.randint(0, 24 * 60))
        cursor.execute(
            "INSERT INTO threats (timestamp, threat_type, description, severity) VALUES (?, ?, ?, ?)",
            (ts.strftime("%Y-%m-%d %H:%M:%S"), threat_type, description, severity)
        )

    conn.commit()
    conn.close()
    print(f"✅ Inserted {n_events} simulated events into {DB_FILE}")


if __name__ == "__main__":
    generate_daily_batch()
