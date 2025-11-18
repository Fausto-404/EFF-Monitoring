"""
简单的SQLite IP名单存储（无需外部依赖）
提供: init_db, add_ip, remove_ip, get_ips, import_from_file, export_to_file, migrate_from_files
"""
import sqlite3
from pathlib import Path
from typing import List, Tuple


def init_db(db_path: str):
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_type TEXT NOT NULL,
            ip TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def add_ip(db_path: str, list_type: str, ip: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("INSERT OR IGNORE INTO ip_list (list_type, ip) VALUES (?, ?)", (list_type, ip))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def remove_ip(db_path: str, ip: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM ip_list WHERE ip = ?", (ip,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_ips(db_path: str, list_type: str) -> List[str]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT ip FROM ip_list WHERE list_type = ? ORDER BY id ASC", (list_type,))
        rows = cur.fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


def import_from_file(db_path: str, list_type: str, file_path: str) -> int:
    count = 0
    init_db(db_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            added = add_ip(db_path, list_type, line)
            if added:
                count += 1
    return count


def export_to_file(db_path: str, list_type: str, file_path: str) -> int:
    ips = get_ips(db_path, list_type)
    with open(file_path, 'w', encoding='utf-8') as f:
        for ip in ips:
            f.write(ip + '\n')
    return len(ips)


def migrate_from_files(db_path: str, whitelist_path: str = None, blacklist_path: str = None) -> Tuple[int, int]:
    """将文本名单迁移到DB，返回 (wh_count, bl_count)"""
    init_db(db_path)
    wcount = 0
    bcount = 0
    if whitelist_path:
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if add_ip(db_path, 'whitelist', line):
                        wcount += 1
        except Exception:
            pass

    if blacklist_path:
        try:
            with open(blacklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if add_ip(db_path, 'blacklist', line):
                        bcount += 1
        except Exception:
            pass

    return wcount, bcount
