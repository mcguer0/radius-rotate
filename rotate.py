#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Массовое создание и ротация пользователей FreeRADIUS/daloRADIUS по списку префиксов.

Возможности:
- Для каждого заданного префикса создаёт одну новую учётку:
    username = PREFIX + 32 символа [a-zA-Z0-9]
    password = 64 символов [a-zA-Z0-9 + punctuation]
    Expiration = через EXPIRE_MONTHS месяцев (локальное время сервера)
- После создания удаляет все ПРОСРОЧЕННЫЕ учётки, чьи username начинаются с данных префиксов.
  Удаление затрагивает: radcheck, radreply, radusergroup, userinfo. (radacct остаётся)

Зависимости:
    pip install pymysql

Переменные окружения (пример см. ниже):
    RADIUS_DB_HOST, RADIUS_DB_PORT, RADIUS_DB_USER, RADIUS_DB_PASS, RADIUS_DB_NAME
    RADIUS_PREFIXES="usfo_,wifi-,corp_"   # список префиксов через запятую
    RADIUS_ENABLE_GROUP=1|0
    RADIUS_GROUP_NAME="default"
    RADIUS_FILL_USERINFO=1|0
    RADIUS_PASS_PUNCT="!#$%&()*+,-./:;<=>?@[]^_{|}~"   # опционально, чтобы исключить кавычки/бэкслеш и т.п.
    RADIUS_EXPIRE_MONTHS=1
    RADIUS_DELETE_EXPIRED=1|0   # включить/выключить удаление просроченных (по умолчанию 1)
"""

import os
import sys
import secrets
import string
import pymysql
from typing import List, Tuple, Optional
from datetime import datetime, timezone, date, timedelta

# ---------- НАСТРОЙКИ ----------
DB_HOST = os.getenv("RADIUS_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("RADIUS_DB_PORT", "3306"))
DB_USER = os.getenv("RADIUS_DB_USER", "username")
DB_PASS = os.getenv("RADIUS_DB_PASS", "pass")
DB_NAME = os.getenv("RADIUS_DB_NAME", "db")

# Список префиксов: "usfo_,wifi-,corp_"
PREFIXES = [p.strip() for p in os.getenv("RADIUS_PREFIXES", "").split(",") if p.strip()]
if not PREFIXES:
    # Фолбэк — совместимость со старым скриптом
    single = os.getenv("RADIUS_PREFIX", "wifi-").strip()
    if single:
        PREFIXES = [single]

ENABLE_GROUP = os.getenv("RADIUS_ENABLE_GROUP", "1") == "1"
GROUP_NAME = os.getenv("RADIUS_GROUP_NAME", "default")
FILL_USERINFO = os.getenv("RADIUS_FILL_USERINFO", "1") == "1"
CUSTOM_PUNCT = os.getenv("RADIUS_PASS_PUNCT")  # например "!#$%&()*+,-./:;<=>?@[]^_{|}~"
EXPIRE_MONTHS = int(os.getenv("RADIUS_EXPIRE_MONTHS", "1"))
DELETE_EXPIRED = os.getenv("RADIUS_DELETE_EXPIRED", "1") == "1"

# Таблицы
TBL_RADCHECK = "radcheck"
TBL_RADREPLY = "radreply"
TBL_RADUSERGROUP = "radusergroup"
TBL_USERINFO = "userinfo"

# ---------- УТИЛИТЫ ГЕНЕРАЦИИ ----------

def random_username(prefix: str, tail_len: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(tail_len))

def random_password(length: int = 64) -> str:
    punctuation = CUSTOM_PUNCT if CUSTOM_PUNCT is not None else string.punctuation
    alphabet = string.ascii_letters + string.digits + punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------- ДАТЫ / EXPIRATION ----------

def last_day_of_month(year: int, month: int) -> int:
    if month == 12:
        ny, nm = year + 1, 1
    else:
        ny, nm = year, month + 1
    return (date(ny, nm, 1) - timedelta(days=1)).day

def add_months_keep_clock(dt: datetime, months: int) -> datetime:
    y, m = dt.year, dt.month
    m2 = m + months
    y2 = y + (m2 - 1) // 12
    m2 = (m2 - 1) % 12 + 1
    d2 = min(dt.day, last_day_of_month(y2, m2))
    return datetime(y2, m2, d2, dt.hour, dt.minute, dt.second)

def english_expiration(dt: datetime) -> str:
    months = ["", "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    return f"{dt.day:02d} {months[dt.month]} {dt.year} {dt:%H:%M:%S}"

def expiration_in_months(months: int = 1) -> str:
    now_local = datetime.now()
    exp_dt = add_months_keep_clock(now_local, months)
    return english_expiration(exp_dt)

def parse_expiration(value: str) -> Optional[datetime]:
    """
    Парсим 'DD Mon YYYY HH:MM:SS' (англ. месяцы) в naive datetime (локальное).
    Возврат None, если формат неожиданный.
    """
    try:
        # Быстрая безопасная разборка без локали
        parts = value.strip().split()
        if len(parts) < 4:
            return None
        day = int(parts[0])
        mon_str = parts[1]
        year = int(parts[2])
        time_str = parts[3]
        h, mi, s = [int(x) for x in time_str.split(":")]
        months = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
        month = months.get(mon_str)
        if not month:
            return None
        return datetime(year, month, day, h, mi, s)
    except Exception:
        return None

# ---------- SQL ХЕЛПЕРЫ ----------

NUMERIC_TYPES = {"int", "bigint", "mediumint", "smallint", "tinyint"}

def get_column_type(cur, table: str, column: str) -> Optional[str]:
    cur.execute("""
        SELECT DATA_TYPE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s
        LIMIT 1
    """, (table, column))
    row = cur.fetchone()
    return row[0].lower() if row else None

def as_schema_timestamp(cur, table: str, column: str, now_dt: datetime):
    coltype = (get_column_type(cur, table, column) or "").lower()
    if coltype in NUMERIC_TYPES:
        return int(now_dt.timestamp())  # epoch UTC
    return now_dt  # Python datetime для DATETIME/TIMESTAMP

# ---------- ОПЕРАЦИИ С ТАБЛИЦАМИ RADIUS ----------

def username_exists(cur, username: str) -> bool:
    cur.execute(f"SELECT 1 FROM {TBL_RADCHECK} WHERE username=%s LIMIT 1", (username,))
    return cur.fetchone() is not None

def create_user(cur, prefix: str, expire_months: int) -> Tuple[str, str, str]:
    # генерируем уникальный username (на случай крайне редкой коллизии)
    for _ in range(5):
        username = random_username(prefix, 32)
        if not username_exists(cur, username):
            break
    else:
        raise RuntimeError("Не удалось подобрать уникальный username за 5 попыток")

    password = random_password(64)
    expiration_str = expiration_in_months(expire_months)

    # Пароль
    cur.execute(
        f"INSERT INTO {TBL_RADCHECK} (username, attribute, op, value) VALUES (%s,'Cleartext-Password',':=',%s)",
        (username, password)
    )
    # Expiration
    cur.execute(
        f"INSERT INTO {TBL_RADCHECK} (username, attribute, op, value) VALUES (%s,'Expiration',':=',%s)",
        (username, expiration_str)
    )

    # Группа (опционально)
    if ENABLE_GROUP and GROUP_NAME:
        cur.execute(
            f"INSERT INTO {TBL_RADUSERGROUP} (username, groupname, priority) VALUES (%s,%s,%s)",
            (username, GROUP_NAME, 1)
        )

    # userinfo (опционально)
    if FILL_USERINFO:
        try:
            cur.execute(f"SHOW COLUMNS FROM {TBL_USERINFO}")
            cols = [r[0] for r in cur.fetchall()]
            cols_set = set(cols)

            now_utc = datetime.now(timezone.utc)

            fields = ["username"]
            placeholders = ["%s"]
            values = [username]

            for fld in ["firstname","lastname","department","company","phone","mobile","email","notes"]:
                if fld in cols_set:
                    fields.append(fld); placeholders.append("%s"); values.append("")

            for fld in ["creationdate", "updatedate"]:
                if fld in cols_set:
                    fields.append(fld); placeholders.append("%s")
                    values.append(as_schema_timestamp(cur, TBL_USERINFO, fld, now_utc))

            sql = f"INSERT INTO {TBL_USERINFO} ({', '.join(fields)}) VALUES ({', '.join(placeholders)})"
            cur.execute(sql, values)
        except pymysql.err.ProgrammingError:
            # userinfo отсутствует — просто пропускаем
            pass

    return username, password, expiration_str

def delete_user_everywhere(cur, username: str):
    for tbl in (TBL_RADCHECK, TBL_RADREPLY, TBL_RADUSERGROUP, TBL_USERINFO):
        try:
            cur.execute(f"DELETE FROM {tbl} WHERE username=%s", (username,))
        except pymysql.err.ProgrammingError:
            # Таблицы может не быть (например, userinfo) — игнорируем
            pass

def collect_expired_usernames_for_prefix(cur, prefix: str) -> List[str]:
    """
    Ищем просроченные username для конкретного префикса.
    Берём все Expiration по префиксу, парсим в python и сравниваем с локальным now().
    """
    # Чтобы underscore и % в префиксе не работали как wildcard в LIKE, фильтруем в питоне:
    cur.execute(
        f"SELECT username, value FROM {TBL_RADCHECK} WHERE attribute='Expiration'"
    )
    rows = cur.fetchall()

    now_local = datetime.now()
    expired = []
    for uname, exp_val in rows:
        if not isinstance(uname, str) or not uname.startswith(prefix):
            continue
        if not isinstance(exp_val, (str, bytes)):
            continue
        if isinstance(exp_val, bytes):
            try:
                exp_val = exp_val.decode("utf-8", "ignore")
            except Exception:
                continue
        dt = parse_expiration(exp_val)
        if dt and dt < now_local:
            expired.append(uname)
    return expired

# ---------- MAIN ----------

def main():
    if not PREFIXES:
        print("ERROR: не задан ни один префикс. Укажите RADIUS_PREFIXES или RADIUS_PREFIX.", file=sys.stderr)
        sys.exit(2)

    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME,
            autocommit=False, charset="utf8mb4", cursorclass=pymysql.cursors.Cursor
        )
    except Exception as e:
        print("ERROR: не удалось подключиться к БД:", e, file=sys.stderr)
        sys.exit(2)

    created = []  # [(prefix, username, password, expiration)]
    deleted = []  # [(prefix, username)]

    try:
        with conn.cursor() as cur:
            # 1) Создание по каждому префиксу
            for pref in PREFIXES:
                u, p, exp = create_user(cur, pref, EXPIRE_MONTHS)
                created.append((pref, u, p, exp))

            # 2) Удаление просроченных по каждому префиксу
            if DELETE_EXPIRED:
                for pref in PREFIXES:
                    to_del = collect_expired_usernames_for_prefix(cur, pref)
                    for uname in to_del:
                        delete_user_everywhere(cur, uname)
                        deleted.append((pref, uname))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()

    # --- РЕЗЮМЕ ---
    print("=== Created users ===")
    for pref, u, p, exp in created:
        print(f"[{pref}]")
        print(f"  Username  : {u}")
        print(f"  Password  : {p}")
        print(f"  Expires at: {exp} (local)")

    if DELETE_EXPIRED:
        print("\n=== Deleted expired users ===")
        if not deleted:
            print("  (none)")
        else:
            for pref, u in deleted:
                print(f"  [{pref}] {u}")
    else:
        print("\nNOTE: Удаление просроченных отключено (RADIUS_DELETE_EXPIRED=0)")

if __name__ == "__main__":
    main()
