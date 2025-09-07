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
import json
import secrets
import string
import pymysql
import subprocess
import shutil
import platform
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timezone, date, timedelta

# ---------- КОНФИГ ----------
CONFIG_FILE = os.getenv("RADIUS_CONFIG_FILE", "config.json")

def load_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    # Загружаем из файла, если есть
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    cfg.update(data)
        except Exception:
            # Если не удалось прочитать/распарсить — игнорируем
            pass

    # Переопределяем переменными окружения (если заданы)
    env_map = {
        "RADIUS_DB_HOST": os.getenv("RADIUS_DB_HOST"),
        "RADIUS_DB_PORT": os.getenv("RADIUS_DB_PORT"),
        "RADIUS_DB_USER": os.getenv("RADIUS_DB_USER"),
        "RADIUS_DB_PASS": os.getenv("RADIUS_DB_PASS"),
        "RADIUS_DB_NAME": os.getenv("RADIUS_DB_NAME"),
        "RADIUS_PREFIXES": os.getenv("RADIUS_PREFIXES"),
        "RADIUS_ENABLE_GROUP": os.getenv("RADIUS_ENABLE_GROUP"),
        "RADIUS_GROUP_NAME": os.getenv("RADIUS_GROUP_NAME"),
        "RADIUS_FILL_USERINFO": os.getenv("RADIUS_FILL_USERINFO"),
        "RADIUS_PASS_PUNCT": os.getenv("RADIUS_PASS_PUNCT"),
        "RADIUS_EXPIRE_MONTHS": os.getenv("RADIUS_EXPIRE_MONTHS"),
        "RADIUS_DELETE_EXPIRED": os.getenv("RADIUS_DELETE_EXPIRED"),
        "RADIUS_COUNT_PER_PREFIX": os.getenv("RADIUS_COUNT_PER_PREFIX"),
        # Совместимость со старым скриптом (один префикс)
        "RADIUS_PREFIX": os.getenv("RADIUS_PREFIX"),
    }
    for k, v in env_map.items():
        if v is not None and v != "":
            cfg[k] = v

    # Значения по умолчанию
    cfg.setdefault("RADIUS_DB_HOST", "127.0.0.1")
    cfg.setdefault("RADIUS_DB_PORT", 3306)
    cfg.setdefault("RADIUS_DB_USER", "username")
    cfg.setdefault("RADIUS_DB_PASS", "pass")
    cfg.setdefault("RADIUS_DB_NAME", "db")
    cfg.setdefault("RADIUS_ENABLE_GROUP", True)
    cfg.setdefault("RADIUS_GROUP_NAME", "default")
    cfg.setdefault("RADIUS_FILL_USERINFO", True)
    cfg.setdefault("RADIUS_PASS_PUNCT", None)
    cfg.setdefault("RADIUS_EXPIRE_MONTHS", 1)
    cfg.setdefault("RADIUS_DELETE_EXPIRED", True)
    cfg.setdefault("RADIUS_COUNT_PER_PREFIX", 1)

    # Приводим типы
    # Порты/числа
    for int_key in ("RADIUS_DB_PORT", "RADIUS_EXPIRE_MONTHS", "RADIUS_COUNT_PER_PREFIX"):
        try:
            cfg[int_key] = int(cfg.get(int_key))
        except Exception:
            cfg[int_key] = 0 if int_key == "RADIUS_DB_PORT" else 1

    # Булевы (могут прийти как строки "1"/"0")
    def to_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        s = str(v).strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    for bkey in ("RADIUS_ENABLE_GROUP", "RADIUS_FILL_USERINFO", "RADIUS_DELETE_EXPIRED"):
        cfg[bkey] = to_bool(cfg.get(bkey))

    # Префиксы
    prefixes: List[str] = []
    if isinstance(cfg.get("RADIUS_PREFIXES"), list):
        prefixes = [str(p).strip() for p in cfg["RADIUS_PREFIXES"] if str(p).strip()]
    elif isinstance(cfg.get("RADIUS_PREFIXES"), str):
        prefixes = [p.strip() for p in str(cfg["RADIUS_PREFIXES"]).split(",") if p.strip()]
    if not prefixes:
        single = str(cfg.get("RADIUS_PREFIX", "")).strip() or os.getenv("RADIUS_PREFIX", "wifi-").strip()
        if single:
            prefixes = [single]
    cfg["RADIUS_PREFIXES"] = prefixes

    # Пунктуация пароля: пустая строка -> None
    if cfg.get("RADIUS_PASS_PUNCT") in ("", None):
        cfg["RADIUS_PASS_PUNCT"] = None

    return cfg

def save_config(cfg: Dict[str, Any]) -> None:
    to_save = cfg.copy()
    # Не сохраняем устаревший одиночный ключ
    to_save.pop("RADIUS_PREFIX", None)
    # Нормализуем булевы значения
    # (json нормально сохраняет bool)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(to_save, f, ensure_ascii=False, indent=2)

def validate_config(cfg: Dict[str, Any], check_db: bool = False) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    # Базовые проверки значений
    if not str(cfg.get("RADIUS_DB_HOST", "")).strip():
        errors.append("DB host пустой")
    try:
        port = int(cfg.get("RADIUS_DB_PORT", 0))
        if port <= 0 or port > 65535:
            errors.append("DB port должен быть в диапазоне 1..65535")
    except Exception:
        errors.append("DB port должен быть числом")

    if not str(cfg.get("RADIUS_DB_USER", "")).strip():
        errors.append("DB user пустой")
    if not str(cfg.get("RADIUS_DB_NAME", "")).strip():
        errors.append("DB name пустой")

    prefixes = cfg.get("RADIUS_PREFIXES", []) or []
    if not isinstance(prefixes, list) or not prefixes:
        errors.append("Список префиксов пустой")
    else:
        for p in prefixes:
            if not str(p).strip():
                errors.append("Обнаружен пустой префикс")
            if any(ch.isspace() for ch in str(p)):
                errors.append(f"Префикс содержит пробелы: '{p}'")

    try:
        cnt = int(cfg.get("RADIUS_COUNT_PER_PREFIX", 1))
        if cnt < 1:
            errors.append("Кол-во аккаунтов на префикс должно быть >= 1")
    except Exception:
        errors.append("Кол-во аккаунтов на префикс должно быть числом")

    try:
        months = int(cfg.get("RADIUS_EXPIRE_MONTHS", 1))
        if months < 1 or months > 120:
            errors.append("Срок действия (месяцев) должен быть в диапазоне 1..120")
    except Exception:
        errors.append("Срок действия (месяцев) должен быть числом")

    if str(cfg.get("RADIUS_ENABLE_GROUP", False)).lower() in ("true", "1") or bool(cfg.get("RADIUS_ENABLE_GROUP", False)):
        if not str(cfg.get("RADIUS_GROUP_NAME", "")).strip():
            errors.append("Имя группы пустое при включённом назначении группы")

    # Проверка подключения к БД и критичных таблиц
    if check_db and not errors:
        try:
            conn = pymysql.connect(
                host=str(cfg.get("RADIUS_DB_HOST")),
                port=int(cfg.get("RADIUS_DB_PORT")),
                user=str(cfg.get("RADIUS_DB_USER")),
                password=str(cfg.get("RADIUS_DB_PASS", "")),
                database=str(cfg.get("RADIUS_DB_NAME")),
                autocommit=True,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.Cursor,
            )
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    # Обязательная таблица radcheck
                    cur.execute("SHOW TABLES LIKE 'radcheck'")
                    if not cur.fetchone():
                        errors.append("Не найдена обязательная таблица 'radcheck'")
                    # Если нужна группа — проверим наличие radusergroup
                    need_group = bool(cfg.get("RADIUS_ENABLE_GROUP", False))
                    if need_group:
                        cur.execute("SHOW TABLES LIKE 'radusergroup'")
                        if not cur.fetchone():
                            errors.append("Включено назначение группы, но таблица 'radusergroup' не найдена")
            finally:
                conn.close()
        except Exception as e:
            errors.append(f"Ошибка подключения к БД: {e}")

    return (len(errors) == 0), errors

def interactive_config():
    print("=== Настройка конфигурации ===")
    base_cfg = load_config()

    def prompt(text: str, default: Optional[str] = None) -> str:
        suffix = f" [{default}]" if default not in (None, "") else ""
        while True:
            val = input(f"{text}{suffix}: ").strip()
            if val:
                return val
            if default is not None:
                return str(default)

    def prompt_int(text: str, default: int) -> int:
        while True:
            s = input(f"{text} [{default}]: ").strip()
            if not s:
                return default
            try:
                return int(s)
            except ValueError:
                print("Введите целое число.")

    def prompt_bool(text: str, default: bool) -> bool:
        d = "y" if default else "n"
        while True:
            s = input(f"{text} (y/n) [{d}]: ").strip().lower()
            if s == "":
                return default
            if s in ("y", "yes", "1", "true", "on"):
                return True
            if s in ("n", "no", "0", "false", "off"):
                return False
            print("Введите y или n.")

    while True:
        cfg = base_cfg.copy()
        # Подключение к БД
        cfg["RADIUS_DB_HOST"] = prompt("DB host", str(cfg.get("RADIUS_DB_HOST", "127.0.0.1")))
        cfg["RADIUS_DB_PORT"] = prompt_int("DB port", int(cfg.get("RADIUS_DB_PORT", 3306)))
        cfg["RADIUS_DB_USER"] = prompt("DB user", str(cfg.get("RADIUS_DB_USER", "username")))
        cfg["RADIUS_DB_PASS"] = prompt("DB password", str(cfg.get("RADIUS_DB_PASS", "pass")))
        cfg["RADIUS_DB_NAME"] = prompt("DB name", str(cfg.get("RADIUS_DB_NAME", "db")))

        # Префиксы
        current_prefixes = cfg.get("RADIUS_PREFIXES", [])
        pref_default = ",".join(current_prefixes) if current_prefixes else "wifi-"
        pref_str = prompt("Префиксы (через запятую)", pref_default)
        cfg["RADIUS_PREFIXES"] = [p.strip() for p in pref_str.split(",") if p.strip()]

        # Количество создаваемых аккаунтов на каждый префикс
        cfg["RADIUS_COUNT_PER_PREFIX"] = prompt_int("Кол-во аккаунтов на префикс", int(cfg.get("RADIUS_COUNT_PER_PREFIX", 1)))

        # Время ротации (в месяцах)
        cfg["RADIUS_EXPIRE_MONTHS"] = prompt_int("Срок действия (месяцев)", int(cfg.get("RADIUS_EXPIRE_MONTHS", 1)))

        # Прочие опции
        cfg["RADIUS_DELETE_EXPIRED"] = prompt_bool("Удалять просроченные", bool(cfg.get("RADIUS_DELETE_EXPIRED", True)))
        cfg["RADIUS_ENABLE_GROUP"] = prompt_bool("Назначать группу", bool(cfg.get("RADIUS_ENABLE_GROUP", True)))
        if cfg["RADIUS_ENABLE_GROUP"]:
            cfg["RADIUS_GROUP_NAME"] = prompt("Имя группы", str(cfg.get("RADIUS_GROUP_NAME", "default")))
        cfg["RADIUS_FILL_USERINFO"] = prompt_bool("Заполнять userinfo", bool(cfg.get("RADIUS_FILL_USERINFO", True)))

        # Набор пунктуации для пароля (пусто = по умолчанию Python)
        punct_default = cfg.get("RADIUS_PASS_PUNCT") or ""
        punct = input(f"Пунктуация для паролей (опционально) [{punct_default}]: ").strip()
        cfg["RADIUS_PASS_PUNCT"] = punct if punct != "" else None

        ok, errs = validate_config(cfg, check_db=True)
        if ok:
            save_config(cfg)
            print(f"Конфигурация сохранена в {CONFIG_FILE}")
            return 0
        else:
            print("\nОбнаружены проблемы с конфигурацией:")
            for e in errs:
                print(f" - {e}")
            ans = input("Повторить ввод? (Y/n) ").strip().lower()
            if ans in ("n", "no"):
                # Разрешаем сохранить как есть, если пользователь настаивает
                save_config(cfg)
                print(f"Конфигурация сохранена в {CONFIG_FILE} (с предупреждениями)")
                return 0


# Загрузка конфигурации при старте
CFG = load_config()

# ---------- НАСТРОЙКИ (из CFG) ----------
DB_HOST = CFG["RADIUS_DB_HOST"]
DB_PORT = int(CFG["RADIUS_DB_PORT"])
DB_USER = CFG["RADIUS_DB_USER"]
DB_PASS = CFG["RADIUS_DB_PASS"]
DB_NAME = CFG["RADIUS_DB_NAME"]

# Список префиксов: "usfo_,wifi-,corp_"
PREFIXES = CFG.get("RADIUS_PREFIXES", [])

ENABLE_GROUP = bool(CFG.get("RADIUS_ENABLE_GROUP", True))
GROUP_NAME = CFG.get("RADIUS_GROUP_NAME", "default")
FILL_USERINFO = bool(CFG.get("RADIUS_FILL_USERINFO", True))
CUSTOM_PUNCT = CFG.get("RADIUS_PASS_PUNCT")  # например "!#$%&()*+,-./:;<=>?@[]^_{|}~"
EXPIRE_MONTHS = int(CFG.get("RADIUS_EXPIRE_MONTHS", 1))
DELETE_EXPIRED = bool(CFG.get("RADIUS_DELETE_EXPIRED", True))
COUNT_PER_PREFIX = int(CFG.get("RADIUS_COUNT_PER_PREFIX", 1))

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

def expired_expiration_str() -> str:
    past = datetime.now() - timedelta(days=1)
    return english_expiration(past)

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

def list_users_by_prefix(cur, prefix: str) -> List[Tuple[str, str]]:
    cur.execute(
        f"SELECT username, value FROM {TBL_RADCHECK} WHERE attribute='Expiration'"
    )
    rows = cur.fetchall()
    result: List[Tuple[str, str]] = []
    for uname, exp_val in rows:
        if isinstance(uname, str) and uname.startswith(prefix):
            if isinstance(exp_val, bytes):
                try:
                    exp_val = exp_val.decode("utf-8", "ignore")
                except Exception:
                    exp_val = ""
            result.append((uname, str(exp_val)))
    return result

def set_user_expiration(cur, username: str, months: int) -> str:
    if months <= 0:
        exp_str = expired_expiration_str()
    else:
        exp_str = expiration_in_months(months)
    # update or insert
    cur.execute(
        f"SELECT id FROM {TBL_RADCHECK} WHERE username=%s AND attribute='Expiration' LIMIT 1",
        (username,),
    )
    row = cur.fetchone()
    if row:
        cur.execute(
            f"UPDATE {TBL_RADCHECK} SET value=%s WHERE username=%s AND attribute='Expiration'",
            (exp_str, username),
        )
    else:
        cur.execute(
            f"INSERT INTO {TBL_RADCHECK} (username, attribute, op, value) VALUES (%s,'Expiration',':=',%s)",
            (username, exp_str),
        )
    return exp_str

def manage_menu():
    print("=== Управление пользователями по префиксам ===")
    if not PREFIXES:
        print("В конфигурации нет префиксов. Запустите -config для настройки.")
    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME,
            autocommit=False, charset="utf8mb4", cursorclass=pymysql.cursors.Cursor
        )
    except Exception as e:
        print("ERROR: не удалось подключиться к БД:", e, file=sys.stderr)
        return 2

    def pick_prefix() -> Optional[str]:
        while True:
            print("\nДоступные префиксы:")
            for i, p in enumerate(PREFIXES, 1):
                print(f"  {i}) {p}")
            print("  0) Ввести вручную")
            print("  q) Выход")
            s = input("Выберите префикс: ").strip().lower()
            if s == "q":
                return None
            if s == "0":
                manual = input("Введите префикс: ").strip()
                return manual if manual else None
            try:
                idx = int(s)
                if 1 <= idx <= len(PREFIXES):
                    return PREFIXES[idx-1]
            except ValueError:
                pass
            print("Неверный выбор.")

    try:
        with conn.cursor() as cur:
            while True:
                pref = pick_prefix()
                if not pref:
                    break

                while True:
                    print(f"\n== Префикс: {pref} ==")
                    print("  1) Показать пользователей")
                    print("  2) Удалить пользователя по username")
                    print("  3) Удалить все просроченные")
                    print("  4) Изменить срок действия пользователя")
                    print("  5) Изменить срок действия всем по префиксу")
                    print("  b) Назад к выбору префикса")
                    print("  q) Выход")
                    choice = input("Выбор: ").strip().lower()

                    if choice == "1":
                        users = list_users_by_prefix(cur, pref)
                        if not users:
                            print("Пользователи не найдены.")
                        else:
                            print(f"Найдено {len(users)} пользователей. Первые 50:")
                            for u, e in users[:50]:
                                print(f"  {u}  |  {e}")

                    elif choice == "2":
                        uname = input("Username для удаления: ").strip()
                        if uname:
                            delete_user_everywhere(cur, uname)
                            conn.commit()
                            print("Удалено (если существовал):", uname)

                    elif choice == "3":
                        to_del = collect_expired_usernames_for_prefix(cur, pref)
                        if not to_del:
                            print("Просроченных нет.")
                        else:
                            print(f"Будут удалены {len(to_del)} пользователей. Подтвердить? (y/N)")
                            ans = input().strip().lower()
                            if ans in ("y", "yes"): 
                                for u in to_del:
                                    delete_user_everywhere(cur, u)
                                conn.commit()
                                print("Удаление выполнено.")

                    elif choice == "4":
                        uname = input("Username: ").strip()
                        if uname:
                            try:
                                m = int(input("Месяцев (0 = сделать просроченным): ").strip() or "1")
                            except ValueError:
                                print("Некорректное число.")
                                continue
                            exp = set_user_expiration(cur, uname, m)
                            conn.commit()
                            print(f"Новая Expiration: {exp}")

                    elif choice == "5":
                        try:
                            m = int(input("Месяцев для всех (0 = просрочить): ").strip() or "1")
                        except ValueError:
                            print("Некорректное число.")
                            continue
                        users = list_users_by_prefix(cur, pref)
                        if not users:
                            print("Пользователи не найдены.")
                        else:
                            print(f"Будет изменён срок у {len(users)} пользователей. Подтвердить? (y/N)")
                            ans = input().strip().lower()
                            if ans in ("y", "yes"):
                                for u, _ in users:
                                    set_user_expiration(cur, u, m)
                                conn.commit()
                                print("Готово.")

                    elif choice == "b":
                        break
                    elif choice == "q":
                        return 0
                    else:
                        print("Неизвестная команда.")
    finally:
        conn.close()
    return 0

def schedule_menu():
    print("=== Настройка расписания (Debian cron) ===")
    if platform.system().lower() == "windows":
        print("Похоже, вы не в Linux/Debian. Настройка cron возможна только на Linux.")
        return 1
    crontab = shutil.which("crontab")
    if not crontab:
        print("Команда 'crontab' не найдена. Установите пакет cron (например, 'sudo apt install cron').")
        return 1

    script_dir = os.path.abspath(os.path.dirname(__file__))
    script_rel = os.path.basename(__file__)
    python_bin = shutil.which("python3") or sys.executable
    cfg_path = os.path.abspath(CONFIG_FILE)
    log_path = input("Путь к лог-файлу [/var/log/radius-rotate.log]: ").strip() or "/var/log/radius-rotate.log"

    print("Выберите частоту:")
    print("  1) Ежедневно в 03:00")
    print("  2) Ежечасно в начале часа")
    print("  3) Каждые N минут")
    print("  4) Еженедельно (день недели и время)")
    print("  5) Ежемесячно (день месяца и время)")
    print("  6) Произвольная cron-строка")
    freq = input("Ваш выбор [1]: ").strip() or "1"

    cron_time = "0 3 * * *"  # daily 03:00
    if freq == "2":
        cron_time = "0 * * * *"
    elif freq == "3":
        try:
            n = int(input("Каждые сколько минут? [30]: ").strip() or "30")
            if n <= 0 or n > 60:
                raise ValueError
            cron_time = f"*/{n} * * * *"
        except ValueError:
            print("Некорректное число, используем каждые 30 минут.")
            cron_time = "*/30 * * * *"
    elif freq == "4":
        dow = input("День недели (0-6, где 0=вс): [1]: ").strip() or "1"
        hm = input("Время HH:MM [03:00]: ").strip() or "03:00"
        try:
            hh, mm = hm.split(":"); int(hh); int(mm)
            cron_time = f"{int(mm)} {int(hh)} * * {dow}"
        except Exception:
            print("Некорректное время, используется 03:00 пн.")
            cron_time = "0 3 * * 1"
    elif freq == "5":
        dom = input("День месяца (1-28) [1]: ").strip() or "1"
        hm = input("Время HH:MM [03:00]: ").strip() or "03:00"
        try:
            hh, mm = hm.split(":"); int(hh); int(mm); int(dom)
            cron_time = f"{int(mm)} {int(hh)} {int(dom)} * *"
        except Exception:
            print("Некорректные значения, используется 1 число 03:00.")
            cron_time = "0 3 1 * *"
    elif freq == "6":
        cron_time = input("Cron-строка (мин час дом мес дов): ").strip() or "0 3 * * *"

    # Команда: перейти в каталог скрипта, задать путь конфига и вызвать python
    tag = "# RADIUS_ROTATE_AUTO"
    command = (
        f"cd {shlex_quote(script_dir)} && "
        f"RADIUS_CONFIG_FILE={shlex_quote(cfg_path)} "
        f"{shlex_quote(python_bin)} {shlex_quote(script_rel)} >> {shlex_quote(log_path)} 2>&1 {tag}"
    )
    line = f"{cron_time} {command}"

    # Считываем текущую crontab
    try:
        res = subprocess.run([crontab, "-l"], capture_output=True, text=True)
        existing = res.stdout.splitlines() if res.returncode == 0 else []
    except Exception as e:
        print("Не удалось прочитать crontab:", e)
        return 1

    # Удаляем старые записи с тегом
    new_lines = [l for l in existing if tag not in l]
    new_lines.append(line)
    new_text = "\n".join(new_lines) + "\n"

    try:
        res = subprocess.run([crontab, "-"], input=new_text, text=True, capture_output=True)
        if res.returncode != 0:
            print("Ошибка установки crontab:", res.stderr.strip())
            return 1
    except Exception as e:
        print("Не удалось установить crontab:", e)
        return 1

    print("Запись в планировщике установлена:")
    print(line)
    return 0

def shlex_quote(s: str) -> str:
    # Простая кроссплатформенная экранизация для shell
    if not s:
        return "''"
    if all(c.isalnum() or c in "@%_+=:,./-" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"

def main():
    # Обработка ключа -config/--config
    if any(arg in ("-config", "--config") for arg in sys.argv[1:]):
        sys.exit(interactive_config())
    # Обработка ключа -manage/--manage
    if any(arg in ("-manage", "--manage") for arg in sys.argv[1:]):
        sys.exit(manage_menu())
    # Обработка ключа -schedule/--schedule (Debian cron)
    if any(arg in ("-schedule", "--schedule") for arg in sys.argv[1:]):
        sys.exit(schedule_menu())

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
            # 1) Создание по каждому префиксу (возможность создать несколько)
            for pref in PREFIXES:
                for _ in range(max(1, COUNT_PER_PREFIX)):
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
