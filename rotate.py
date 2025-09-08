#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Массовое создание и МЕСЯЧНАЯ ротация ПАРОЛЕЙ пользователей FreeRADIUS/daloRADIUS по списку префиксов.

Что делает теперь:
- Не назначает срок годности (Expiration) и не удаляет пользователей.
- Для каждого заданного префикса:
  - При первом запуске создаёт нужное число учёток (COUNT_PER_PREFIX),
    username = PREFIX + 32 символа [a-zA-Z0-9],
    password = 64 символов [a-zA-Z0-9 + punctuation].
  - При последующих запускax меняет пароль у ВСЕХ найденных учёток с этим префиксом.
    (Опционально может дозаполнить недостающее количество до COUNT_PER_PREFIX.)

Зависимости:
    pip install pymysql

Переменные окружения (пример см. ниже):
    RADIUS_DB_HOST, RADIUS_DB_PORT, RADIUS_DB_USER, RADIUS_DB_PASS, RADIUS_DB_NAME
    RADIUS_PREFIXES="usfo_,wifi-,corp_"   # список префиксов через запятую
    RADIUS_ENABLE_GROUP=1|0
    RADIUS_GROUP_NAME="default"
    RADIUS_FILL_USERINFO=1|0
    RADIUS_PASS_PUNCT="!#$%&()*+,-./:;<=>?@[]^_{|}~"   # опционально, чтобы исключить кавычки/бэкслеш и т.п.
    RADIUS_COUNT_PER_PREFIX=1
    RADIUS_USE_PREFIX=1|0
    RADIUS_PREFIX_POSITION=start|end
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
import pathlib
import ipaddress
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timezone

# ---------- КОНФИГ ----------
CONFIG_FILE = os.getenv("RADIUS_CONFIG_FILE", "config.json")
DRY_RUN = False  # Глобальный флаг "репетиции" без записей в БД

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
        "RADIUS_USE_PREFIX": os.getenv("RADIUS_USE_PREFIX"),
        "RADIUS_PREFIX_POSITION": os.getenv("RADIUS_PREFIX_POSITION"),
        "RADIUS_ENABLE_GROUP": os.getenv("RADIUS_ENABLE_GROUP"),
        "RADIUS_GROUP_NAME": os.getenv("RADIUS_GROUP_NAME"),
        "RADIUS_FILL_USERINFO": os.getenv("RADIUS_FILL_USERINFO"),
        "RADIUS_PASS_PUNCT": os.getenv("RADIUS_PASS_PUNCT"),
        "RADIUS_COUNT_PER_PREFIX": os.getenv("RADIUS_COUNT_PER_PREFIX"),
        "RADIUS_USERNAME_TAIL_LEN": os.getenv("RADIUS_USERNAME_TAIL_LEN"),
        "RADIUS_PASSWORD_LEN": os.getenv("RADIUS_PASSWORD_LEN"),
        # Новые ключи для генерации политики FreeRADIUS
        "RADIUS_ENFORCE_PREFIX_ACCESS": os.getenv("RADIUS_ENFORCE_PREFIX_ACCESS"),
        # Сложные структуры читаем только из файла config.json, но допускаем JSON в переменной окружения как строку
        "RADIUS_ACCESS_POLICIES": os.getenv("RADIUS_ACCESS_POLICIES"),
        # Импорт конфигов FR
        "RADIUS_FR_BASE": os.getenv("RADIUS_FR_BASE"),
        "RADIUS_FR_HUNTGROUPS_PATH": os.getenv("RADIUS_FR_HUNTGROUPS_PATH"),
        "RADIUS_FR_SITE_DEFAULT_PATH": os.getenv("RADIUS_FR_SITE_DEFAULT_PATH"),
        "RADIUS_FR_SERVICE": os.getenv("RADIUS_FR_SERVICE"),
        "RADIUS_FR_MODE": os.getenv("RADIUS_FR_MODE"),  # 'virtual_server' (по умолчанию) или 'huntgroups'
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
    cfg.setdefault("RADIUS_USE_PREFIX", True)
    cfg.setdefault("RADIUS_PREFIX_POSITION", "start")  # start|end
    cfg.setdefault("RADIUS_ENABLE_GROUP", True)
    cfg.setdefault("RADIUS_GROUP_NAME", "default")
    cfg.setdefault("RADIUS_FILL_USERINFO", True)
    cfg.setdefault("RADIUS_PASS_PUNCT", None)
    cfg.setdefault("RADIUS_COUNT_PER_PREFIX", 1)
    cfg.setdefault("RADIUS_USERNAME_TAIL_LEN", 32)
    cfg.setdefault("RADIUS_PASSWORD_LEN", 64)
    # Управление доступом по префиксам и huntgroups
    cfg.setdefault("RADIUS_ENFORCE_PREFIX_ACCESS", False)
    cfg.setdefault("RADIUS_ACCESS_POLICIES", [])
    # Пути FreeRADIUS по умолчанию (Debian FR 3.x)
    cfg.setdefault("RADIUS_FR_BASE", "/etc/freeradius/3.0")
    cfg.setdefault("RADIUS_FR_HUNTGROUPS_PATH", None)  # если None, возьмём по базе
    cfg.setdefault("RADIUS_FR_SITE_DEFAULT_PATH", None)
    cfg.setdefault("RADIUS_FR_SERVICE", "freeradius")
    cfg.setdefault("RADIUS_FR_MODE", "virtual_server")

    # Приводим типы
    # Порты/числа
    for int_key in ("RADIUS_DB_PORT", "RADIUS_COUNT_PER_PREFIX", "RADIUS_USERNAME_TAIL_LEN", "RADIUS_PASSWORD_LEN"):
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

    for bkey in ("RADIUS_ENABLE_GROUP", "RADIUS_FILL_USERINFO", "RADIUS_USE_PREFIX"):
        cfg[bkey] = to_bool(cfg.get(bkey))
    cfg["RADIUS_ENFORCE_PREFIX_ACCESS"] = to_bool(cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS"))

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

    # Политики доступа: разрешаем задать как JSON-строку в окружении
    pol_val = cfg.get("RADIUS_ACCESS_POLICIES")
    if isinstance(pol_val, str):
        try:
            parsed = json.loads(pol_val)
            if isinstance(parsed, list):
                cfg["RADIUS_ACCESS_POLICIES"] = parsed
        except Exception:
            # Оставим как есть, если не JSON
            pass

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
    use_prefix = bool(cfg.get("RADIUS_USE_PREFIX", True))
    if use_prefix:
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

    # Параметры Expiration устарели и не используются

    # Валидация политик доступа (минимальная)
    policies = cfg.get("RADIUS_ACCESS_POLICIES", [])
    if policies and not isinstance(policies, list):
        errors.append("RADIUS_ACCESS_POLICIES должен быть списком объектов")
    elif isinstance(policies, list):
        for idx, p in enumerate(policies, 1):
            if not isinstance(p, dict):
                errors.append(f"Политика #{idx} должна быть объектом")
                continue
            if not p.get("prefix"):
                errors.append(f"Политика #{idx}: не указан 'prefix'")
            # поля необязательны, но хотя бы одно условие должно быть
            has_selector = any(k in p for k in ("cidrs", "nas_identifier_regex", "called_station_regex"))
            if not has_selector:
                errors.append(f"Политика #{idx}: не заданы условия (cidrs/nas_identifier_regex/called_station_regex)")
    mode = str(cfg.get("RADIUS_FR_MODE", "virtual_server")).strip().lower()
    if mode not in ("virtual_server", "huntgroups"):
        errors.append("RADIUS_FR_MODE должен быть 'virtual_server' или 'huntgroups'")

    # Длины
    try:
        name_tail = int(cfg.get("RADIUS_USERNAME_TAIL_LEN", 32))
        if name_tail < 1 or name_tail > 128:
            errors.append("Длина случайной части username должна быть 1..128")
    except Exception:
        errors.append("Длина username должна быть числом")
    try:
        pass_len = int(cfg.get("RADIUS_PASSWORD_LEN", 64))
        if pass_len < 8 or pass_len > 256:
            errors.append("Длина пароля должна быть 8..256")
    except Exception:
        errors.append("Длина пароля должна быть числом")

    pos = str(cfg.get("RADIUS_PREFIX_POSITION", "start")).lower()
    if pos not in ("start", "end"):
        errors.append("Позиция префикса должна быть 'start' или 'end'")

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
        use_pref = bool(cfg.get("RADIUS_USE_PREFIX", True))
        use_pref = prompt_bool("Использовать префиксы в username", use_pref)
        cfg["RADIUS_USE_PREFIX"] = use_pref
        if use_pref:
            current_prefixes = cfg.get("RADIUS_PREFIXES", [])
            pref_default = ",".join(current_prefixes) if current_prefixes else "wifi-"
            pref_str = prompt("Префиксы (через запятую)", pref_default)
            cfg["RADIUS_PREFIXES"] = [p.strip() for p in pref_str.split(",") if p.strip()]
            pos_default = str(cfg.get("RADIUS_PREFIX_POSITION", "start")).lower()
            while True:
                pos = input(f"Расположение префикса (start/end) [{pos_default}]: ").strip().lower() or pos_default
                if pos in ("start", "end"):
                    cfg["RADIUS_PREFIX_POSITION"] = pos
                    break
                print("Введите 'start' или 'end'.")
        else:
            cfg["RADIUS_PREFIXES"] = cfg.get("RADIUS_PREFIXES", [])  # оставим как есть/пусто
            cfg["RADIUS_PREFIX_POSITION"] = str(cfg.get("RADIUS_PREFIX_POSITION", "start")).lower()

        # Количество создаваемых аккаунтов на каждый префикс
        cfg["RADIUS_COUNT_PER_PREFIX"] = prompt_int("Кол-во аккаунтов на префикс", int(cfg.get("RADIUS_COUNT_PER_PREFIX", 1)))

        # Длины
        cfg["RADIUS_USERNAME_TAIL_LEN"] = prompt_int("Длина случайной части username", int(cfg.get("RADIUS_USERNAME_TAIL_LEN", 32)))
        cfg["RADIUS_PASSWORD_LEN"] = prompt_int("Длина пароля", int(cfg.get("RADIUS_PASSWORD_LEN", 64)))

        # Прочие опции
        cfg["RADIUS_ENABLE_GROUP"] = prompt_bool("Назначать группу", bool(cfg.get("RADIUS_ENABLE_GROUP", True)))
        if cfg["RADIUS_ENABLE_GROUP"]:
            cfg["RADIUS_GROUP_NAME"] = prompt("Имя группы", str(cfg.get("RADIUS_GROUP_NAME", "default")))
        cfg["RADIUS_FILL_USERINFO"] = prompt_bool("Заполнять userinfo", bool(cfg.get("RADIUS_FILL_USERINFO", True)))

        # Набор пунктуации для пароля (пусто = по умолчанию Python)
        punct_default = cfg.get("RADIUS_PASS_PUNCT") or ""
        punct = input(f"Пунктуация для паролей (опционально) [{punct_default}]: ").strip()
        cfg["RADIUS_PASS_PUNCT"] = punct if punct != "" else None

        # Политика доступа по префиксам (huntgroups + unlang)
        en_access_default = bool(cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS", False))
        en_access = prompt_bool("Ограничивать доступ по префиксам (huntgroups+unlang)?", en_access_default)
        cfg["RADIUS_ENFORCE_PREFIX_ACCESS"] = en_access
        if en_access:
            setup_now = prompt_bool("Заполнить параметры NAS сейчас? (если нет — будут заготовки)", True)
            policies: List[Dict[str, Any]] = []
            if setup_now:
                pfxs = cfg.get("RADIUS_PREFIXES", []) if cfg.get("RADIUS_USE_PREFIX", True) else []
                if not pfxs:
                    print("Предупреждение: префиксы не заданы или отключены, политики будут пустыми.")
                for pref in pfxs:
                    print(f"\n— Политика для префикса: {pref}")
                    hg_def = default_huntgroup_for_prefix(pref)
                    hg = prompt("Имя huntgroup", hg_def)
                    cidr_str = input("CIDR подсети NAS (через запятую) [0.0.0.0/32]: ").strip() or "0.0.0.0/32"
                    cidrs = [c.strip() for c in cidr_str.split(",") if c.strip()]
                    nasid_str = input("Regex по NAS-Identifier (через запятую) [пропустить]: ").strip()
                    nasid = [r.strip() for r in nasid_str.split(",") if r.strip()] if nasid_str else []
                    called_str = input("Regex по Called-Station-Id (через запятую) [пропустить]: ").strip()
                    called = [r.strip() for r in called_str.split(",") if r.strip()] if called_str else []
                    policies.append({
                        "prefix": pref,
                        "huntgroup": hg,
                        "cidrs": cidrs if cidrs else ["0.0.0.0/32"],
                        "nas_identifier_regex": nasid,
                        "called_station_regex": called,
                    })
            else:
                # Сгенерируем заготовки по префиксам с безопасным плейсхолдером
                for pref in cfg.get("RADIUS_PREFIXES", []) if cfg.get("RADIUS_USE_PREFIX", True) else []:
                    policies.append({
                        "prefix": pref,
                        "huntgroup": default_huntgroup_for_prefix(pref),
                        "cidrs": ["0.0.0.0/32"],
                        "nas_identifier_regex": [],
                        "called_station_regex": [],
                    })
            if policies:
                cfg["RADIUS_ACCESS_POLICIES"] = policies

        ok, errs = validate_config(cfg, check_db=True)
        if ok:
            save_config(cfg)
            print(f"Конфигурация сохранена в {CONFIG_FILE}")
            # Предложим сразу сгенерировать конфиги FreeRADIUS
            if cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS"):
                try:
                    do_render = prompt_bool("Сгенерировать huntgroups и authorize‑сниппет сейчас?", True)
                except Exception:
                    do_render = False
                if do_render:
                    out_path = input("Каталог вывода (или '-' для консоли) [fr-conf]: ").strip() or "fr-conf"
                    export_freeradius_config(cfg, out_path if out_path else None)
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
COUNT_PER_PREFIX = int(CFG.get("RADIUS_COUNT_PER_PREFIX", 1))
USE_PREFIX = bool(CFG.get("RADIUS_USE_PREFIX", True))
PREFIX_POSITION = str(CFG.get("RADIUS_PREFIX_POSITION", "start")).lower()
USERNAME_TAIL_LEN = int(CFG.get("RADIUS_USERNAME_TAIL_LEN", 32))
PASSWORD_LEN = int(CFG.get("RADIUS_PASSWORD_LEN", 64))

# Таблицы
TBL_RADCHECK = "radcheck"
TBL_RADREPLY = "radreply"
TBL_RADUSERGROUP = "radusergroup"
TBL_USERINFO = "userinfo"

# ---------- УТИЛИТЫ ГЕНЕРАЦИИ ----------

def random_username(prefix: str, tail_len: int = None) -> str:
    if tail_len is None:
        tail_len = USERNAME_TAIL_LEN
    alphabet = string.ascii_letters + string.digits
    tail = ''.join(secrets.choice(alphabet) for _ in range(tail_len))
    if not USE_PREFIX:
        return tail
    if PREFIX_POSITION == "end":
        return tail + prefix
    return prefix + tail

def random_password(length: int = None) -> str:
    if length is None:
        length = PASSWORD_LEN
    punctuation = CUSTOM_PUNCT if CUSTOM_PUNCT is not None else string.punctuation
    alphabet = string.ascii_letters + string.digits + punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------- ДАТЫ / EXPIRATION (оставлено для совместимости с manage-меню) ----------

# Удалены вспомогательные функции Expiration — логика срока действия больше не используется

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

def db_execute(cur, sql: str, params: Optional[Tuple]=None):
    if DRY_RUN:
        try:
            q = sql % tuple(repr(x) for x in (params or ()))
        except Exception:
            q = sql
        print("DRY-RUN SQL:", q)
        return 0
    return cur.execute(sql, params or ())

def username_exists(cur, username: str) -> bool:
    cur.execute(f"SELECT 1 FROM {TBL_RADCHECK} WHERE username=%s LIMIT 1", (username,))
    return cur.fetchone() is not None

def create_user(cur, prefix: str) -> Tuple[str, str]:
    # генерируем уникальный username (на случай крайне редкой коллизии)
    for _ in range(5):
        username = random_username(prefix)
        if not username_exists(cur, username):
            break
    else:
        raise RuntimeError("Не удалось подобрать уникальный username за 5 попыток")

    password = random_password()

    # Пароль
    db_execute(
        cur,
        f"INSERT INTO {TBL_RADCHECK} (username, attribute, op, value) VALUES (%s,'Cleartext-Password',':=',%s)",
        (username, password),
    )
    # Ранее здесь добавлялся атрибут Expiration — теперь не назначаем срок действия

    # Группа (опционально)
    if ENABLE_GROUP and GROUP_NAME:
        db_execute(
            cur,
            f"INSERT INTO {TBL_RADUSERGROUP} (username, groupname, priority) VALUES (%s,%s,%s)",
            (username, GROUP_NAME, 1),
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
            db_execute(cur, sql, tuple(values))
        except pymysql.err.ProgrammingError:
            # userinfo отсутствует — просто пропускаем
            pass

    return username, password

def delete_user_everywhere(cur, username: str):
    for tbl in (TBL_RADCHECK, TBL_RADREPLY, TBL_RADUSERGROUP, TBL_USERINFO):
        try:
            db_execute(cur, f"DELETE FROM {tbl} WHERE username=%s", (username,))
        except pymysql.err.ProgrammingError:
            # Таблицы может не быть (например, userinfo) — игнорируем
            pass

def matches_prefix(username: str, prefix: str) -> bool:
    if not isinstance(username, str):
        return False
    if not USE_PREFIX:
        return False
    if PREFIX_POSITION == "end":
        return username.endswith(prefix)
    return username.startswith(prefix)

    # Удалена логика поиска просроченных пользователей

# ---------- MAIN ----------

# ---------- Генерация конфигурации FreeRADIUS ----------

def sanitize_huntgroup_name(name: str) -> str:
    # Допускаем буквы, цифры, '-', '_', '.'
    safe = []
    for ch in name:
        if ch.isalnum() or ch in "-_.":
            safe.append(ch)
        else:
            safe.append("_")
    s = ''.join(safe)
    return s or "hg"

def default_huntgroup_for_prefix(prefix: str) -> str:
    base = prefix.rstrip("-_ ")
    if not base:
        base = "prefix"
    return sanitize_huntgroup_name(f"{base}devs")

def normalize_policies(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    policies = cfg.get("RADIUS_ACCESS_POLICIES", []) or []
    result: List[Dict[str, Any]] = []
    # Автогенерация по RADIUS_PREFIXES, если policies пуст
    if not policies and cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS"):
        for pref in cfg.get("RADIUS_PREFIXES", []) or []:
            result.append({
                "prefix": pref,
                "huntgroup": default_huntgroup_for_prefix(pref),
                # Пустые условия — админ заполнит вручную позже
                # По умолчанию добавим безопасный плейсхолдер, не совпадающий ни с одним реальным NAS
                "cidrs": ["0.0.0.0/32"],
                "nas_identifier_regex": [],
                "called_station_regex": [],
            })
        return result
    # Нормализация типов
    for p in policies:
        if not isinstance(p, dict):
            continue
        pref = str(p.get("prefix", ""))
        hg = str(p.get("huntgroup") or default_huntgroup_for_prefix(pref))
        cidrs = p.get("cidrs") or []
        nasid = p.get("nas_identifier_regex") or []
        called = p.get("called_station_regex") or []
        # Приводим всё к спискам строк
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        if isinstance(nasid, str):
            nasid = [nasid]
        if isinstance(called, str):
            called = [called]
        result.append({
            "prefix": pref,
            "huntgroup": sanitize_huntgroup_name(hg),
            "cidrs": [str(x) for x in cidrs],
            "nas_identifier_regex": [str(x) for x in nasid],
            "called_station_regex": [str(x) for x in called],
        })
    return result

def render_huntgroups_text(policies: List[Dict[str, Any]]) -> str:
    lines = []
    lines.append(f"# radius-rotate generated huntgroups at {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append("# Copy/merge into /etc/freeradius/3.0/huntgroups")
    for p in policies:
        hg = p["huntgroup"]
        for net in p.get("cidrs", []) or []:
            # Поддержка /32 как точного IP и /8,/16,/24 как regex по октетам
            try:
                n = ipaddress.ip_network(str(net), strict=False)
                if isinstance(n, ipaddress.IPv4Network):
                    if n.prefixlen == 32:
                        lines.append(f"{hg}\tNAS-IP-Address == {n.network_address}")
                    elif n.prefixlen in (8, 16, 24):
                        parts = str(n.network_address).split(".")
                        take = n.prefixlen // 8
                        prefix = ".".join(parts[:take])
                        regex = "^" + prefix.replace(".", "\\.") + "."
                        lines.append(f"{hg}\tNAS-IP-Address =~ \"{regex}\"")
                    else:
                        # Сложные маски: деградация до адреса сети (админ может отредактировать вручную)
                        lines.append(f"{hg}\tNAS-IP-Address == {n.network_address}")
                else:
                    # IPv6: используем точное совпадение адреса сети
                    lines.append(f"{hg}\tNAS-IP-Address == {n.network_address}")
            except Exception:
                # Некорректный ввод — пишем как есть (возможно это уже regex)
                esc = str(net).replace('"', '\\"')
                lines.append(f"{hg}\tNAS-IP-Address =~ \"{esc}\"")
        for rx in p.get("nas_identifier_regex", []) or []:
            # NAS-Identifier =~ "regex"
            esc = rx.replace('"', '\\"')
            lines.append(f"{hg}\tNAS-Identifier =~ \"{esc}\"")
        for rx in p.get("called_station_regex", []) or []:
            esc = rx.replace('"', '\\"')
            lines.append(f"{hg}\tCalled-Station-Id =~ \"{esc}\"")
    return "\n".join(lines) + "\n"

def render_unlang_authorize_text(policies: List[Dict[str, Any]]) -> str:
    lines = []
    lines.append("# radius-rotate: add this block to sites-enabled/default 'authorize' after 'preprocess'")
    for p in policies:
        pref = p["prefix"]
        hg = p["huntgroup"]
        # Экранируем спецсимволы в префиксе для regex
        pref_regex = ''.join(['\\' + c if c in "^$.|?*+()[]{}\\" else c for c in pref])
        lines.append(f"if (&Huntgroup-Name == \"{hg}\" && &User-Name !~ /^{pref_regex}/) {{")
        lines.append("    reject")
        lines.append("}")
    return "\n".join(lines) + "\n"

def export_freeradius_config(cfg: Dict[str, Any], out: Optional[str]) -> int:
    policies = normalize_policies(cfg)
    if not policies:
        print("Нет политик для генерации. Задайте RADIUS_ENFORCE_PREFIX_ACCESS=1 и/или RADIUS_ACCESS_POLICIES в config.json")
        return 1
    mode = str(cfg.get("RADIUS_FR_MODE", "virtual_server")).strip().lower()

    out_dir = None
    if out and out != "-":
        out_dir = pathlib.Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)

    if mode == "huntgroups":
        huntgroups_txt = render_huntgroups_text(policies)
        unlang_txt = render_unlang_authorize_text(policies)
        if not out or out == "-":
            print("=== HUNTGROUPS (merge into /etc/freeradius/3.0/huntgroups) ===")
            print(huntgroups_txt)
            print("=== UNLANG AUTHORIZE SNIPPET (sites-enabled/default:authorize) ===")
            print(unlang_txt)
        else:
            (out_dir / "huntgroups.radius-rotate").write_text(huntgroups_txt, encoding="utf-8")
            (out_dir / "authorize.radius-rotate.snippet").write_text(unlang_txt, encoding="utf-8")
            print(f"Сгенерировано: {out_dir / 'huntgroups.radius-rotate'}")
            print(f"Сгенерировано: {out_dir / 'authorize.radius-rotate.snippet'}")
            print("Подключите preprocess в authorize и вставьте сниппет после него.")
        return 0

    # virtual_server mode: по каждой политике создаём виртуальный сервер
    def render_vs(pref: str, vsname: str) -> str:
        pref_regex = ''.join(['\\' + c if c in "^$.|?*+()[]{}\\" else c for c in pref])
        return (
f"# radius-rotate virtual server for prefix '{pref}'\n"
f"server {vsname} {{\n"
f"    authorize {{\n"
f"        if (&User-Name !~ /^{pref_regex}/) {{\n"
f"            reject\n"
f"        }}\n"
f"        preprocess\n"
f"        files\n"
f"        sql\n"
f"    }}\n"
f"    authenticate {{\n"
f"        Auth-Type PAP {{\n"
f"            pap\n"
f"        }}\n"
f"    }}\n"
f"}}\n")

    if not out or out == "-":
        for p in policies:
            vsname = p["huntgroup"]
            print(f"=== SITE {vsname} (sites-available/{vsname}) ===")
            print(render_vs(p["prefix"], vsname))
        print("Подключите клиентов к соответствующим виртуальным серверам (поле 'server' в таблице nas, read_clients=yes).")
        return 0

    # Вывод в каталог: создадим подкаталог sites-available
    sa = out_dir / "sites-available"
    sa.mkdir(parents=True, exist_ok=True)
    for p in policies:
        vsname = p["huntgroup"]
        text = render_vs(p["prefix"], vsname)
        (sa / vsname).write_text(text, encoding="utf-8")
        print(f"Сгенерировано: {sa / vsname}")
    print("Создано содержимое для sites-available/. Создайте symlink в sites-enabled/. И включите read_clients=yes в sql.")
    return 0

def sudo_read_file(path: str) -> Optional[str]:
    try:
        res = subprocess.run(["sudo", "cat", path], capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout
    except Exception:
        pass
    return None

def sudo_write_file(path: str, content: str) -> bool:
    try:
        proc = subprocess.Popen(["sudo", "tee", path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(input=content)
        return proc.returncode == 0
    except Exception:
        return False

def freeradius_paths(cfg: Dict[str, Any]) -> Tuple[str, str]:
    base = str(cfg.get("RADIUS_FR_BASE", "/etc/freeradius/3.0"))
    hunt = cfg.get("RADIUS_FR_HUNTGROUPS_PATH") or os.path.join(base, "mods-config", "preprocess", "huntgroups")
    site_def = cfg.get("RADIUS_FR_SITE_DEFAULT_PATH") or os.path.join(base, "sites-enabled", "default")
    return hunt, site_def

def inject_authorize_block(original: str, snippet: str) -> str:
    begin_marker = "# radius-rotate begin"
    end_marker = "# radius-rotate end"
    # Если блок уже есть — заменить
    if begin_marker in original and end_marker in original:
        pre, rest = original.split(begin_marker, 1)
        _, post = rest.split(end_marker, 1)
        return pre + begin_marker + "\n" + snippet + end_marker + post

    # Иначе найдём authorize { ... }
    lines = original.splitlines()
    n = len(lines)
    start_idx = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("authorize") and s.endswith("{"):
            start_idx = i
            break
    if start_idx == -1:
        # если не нашли — просто добавим в конец
        return original + "\n" + begin_marker + "\n" + snippet + end_marker + "\n"

    # Найдём конец блока по балансу скобок
    brace = 0
    end_idx = -1
    for i in range(start_idx, n):
        brace += lines[i].count("{")
        brace -= lines[i].count("}")
        if brace == 0:
            end_idx = i
            break
    if end_idx == -1:
        # некорректный файл — добавим в конец
        return original + "\n" + begin_marker + "\n" + snippet + end_marker + "\n"

    # Проверим наличие preprocess внутри authorize, если нет — добавим его перед нашим блоком
    auth_block = lines[start_idx:end_idx+1]
    has_pre = any(l.strip().startswith("preprocess") for l in auth_block)
    prep_line = "preprocess\n" if not has_pre else ""

    indent = ""
    # Возьмём отступ первой строки блока
    leading = lines[start_idx]
    indent = leading[:leading.find("authorize")]
    injected = [lines[start_idx]]
    # оставим строки до закрывающей скобки (но вставим наш блок перед ней)
    body = lines[start_idx+1:end_idx]
    # Собираем новый блок
    new_body = []
    if prep_line:
        new_body.append(indent + "    " + prep_line.strip())
    new_body.append(indent + "    " + begin_marker)
    for ln in snippet.strip().splitlines():
        new_body.append(indent + "    " + ln)
    new_body.append(indent + "    " + end_marker)
    injected.extend(new_body)
    injected.append(lines[end_idx])

    # Заменим блок
    return "\n".join(lines[:start_idx] + injected + lines[end_idx+1:]) + ("\n" if not original.endswith("\n") else "")

def import_freeradius_config(cfg: Dict[str, Any], restart: bool = False) -> int:
    if platform.system().lower() != "linux":
        print("Импорт поддерживается только на Linux.", file=sys.stderr)
        return 2
    if shutil.which("sudo") is None:
        print("Не найден 'sudo' в PATH.", file=sys.stderr)
        return 2
    if shutil.which("freeradius") is None:
        print("Не найден бинарник 'freeradius' в PATH.", file=sys.stderr)
        return 2

    policies = normalize_policies(cfg)
    if not policies:
        print("Нет политик для генерации. Включите RADIUS_ENFORCE_PREFIX_ACCESS и задайте политики.")
        return 1
    mode = str(cfg.get("RADIUS_FR_MODE", "virtual_server")).strip().lower()

    if mode == "huntgroups":
        huntgroups_txt = render_huntgroups_text(policies)
        unlang_txt = render_unlang_authorize_text(policies)
        hunt_path, site_def_path = freeradius_paths(cfg)

        # Резервные копии
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        hunt_bak = f"{hunt_path}.radius-rotate.bak.{ts}"
        site_bak = f"{site_def_path}.radius-rotate.bak.{ts}"

        current_default = sudo_read_file(site_def_path)
        if current_default is None:
            print(f"Не удалось прочитать {site_def_path} (нужны права sudo)", file=sys.stderr)
            return 2
        new_default = inject_authorize_block(current_default, unlang_txt)

        subprocess.run(["sudo", "cp", "-a", hunt_path, hunt_bak], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["sudo", "cp", "-a", site_def_path, site_bak], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if not sudo_write_file(hunt_path, huntgroups_txt):
            print("Не удалось записать huntgroups (sudo)", file=sys.stderr)
            return 2
        if not sudo_write_file(site_def_path, new_default):
            print("Не удалось записать default (sudo)", file=sys.stderr)
            return 2

        # Проверка конфигурации
        res = subprocess.run(["sudo", "freeradius", "-XC"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if res.returncode != 0:
            print("Ошибка проверки конфигурации:")
            print(res.stdout)
            subprocess.run(["sudo", "cp", "-a", hunt_bak, hunt_path])
            subprocess.run(["sudo", "cp", "-a", site_bak, site_def_path])
            return 1

        print("Проверка конфигурации пройдена.")
        if restart:
            service = str(cfg.get("RADIUS_FR_SERVICE", "freeradius"))
            r = subprocess.run(["sudo", "systemctl", "restart", service])
            if r.returncode != 0:
                print("Не удалось перезапустить службу.", file=sys.stderr)
                return 1
            print("Служба перезапущена.")
        else:
            print("Изменения записаны. Перезапустите службу FreeRADIUS, чтобы применить их.")
        return 0

    # virtual_server mode
    base = str(cfg.get("RADIUS_FR_BASE", "/etc/freeradius/3.0"))
    sa = os.path.join(base, "sites-available")
    se = os.path.join(base, "sites-enabled")

    # вспомогательные
    def render_vs(pref: str, vsname: str) -> str:
        pref_regex = ''.join(['\\' + c if c in "^$.|?*+()[]{}\\" else c for c in pref])
        return (
f"# radius-rotate virtual server for prefix '{pref}'\n"
f"server {vsname} {{\n"
f"    authorize {{\n"
f"        if (&User-Name !~ /^{pref_regex}/) {{\n"
f"            reject\n"
f"        }}\n"
f"        preprocess\n"
f"        files\n"
f"        sql\n"
f"    }}\n"
f"    authenticate {{\n"
f"        Auth-Type PAP {{\n"
f"            pap\n"
f"        }}\n"
f"    }}\n"
f"}}\n")

    # Удалим старые наши сайты, которых больше нет в политиках
    try:
        res = subprocess.run(["sudo", "ls", "-1", sa], capture_output=True, text=True)
        existing = res.stdout.splitlines() if res.returncode == 0 else []
    except Exception:
        existing = []
    current_names = {p["huntgroup"] for p in policies}
    for fname in existing:
        # Проверим маркер
        path = os.path.join(sa, fname)
        content = sudo_read_file(path) or ""
        if content.startswith("# radius-rotate virtual server for prefix ") and fname not in current_names:
            subprocess.run(["sudo", "rm", "-f", path])
            subprocess.run(["sudo", "rm", "-f", os.path.join(se, fname)])

    # Запишем/включим актуальные
    for p in policies:
        vsname = p["huntgroup"]
        content = render_vs(p["prefix"], vsname)
        if not sudo_write_file(os.path.join(sa, vsname), content):
            print(f"Не удалось записать {sa}/{vsname}", file=sys.stderr)
            return 2
        # symlink в sites-enabled
        subprocess.run(["sudo", "ln", "-sf", os.path.join(sa, vsname), os.path.join(se, vsname)])

    # Проверим конфигурацию
    res = subprocess.run(["sudo", "freeradius", "-XC"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if res.returncode != 0:
        print("Ошибка проверки конфигурации:")
        print(res.stdout)
        return 1

    print("Проверка конфигурации пройдена. Включите в sql read_clients = yes и назначьте NAS.server для нужных клиентов.")
    if restart:
        service = str(cfg.get("RADIUS_FR_SERVICE", "freeradius"))
        r = subprocess.run(["sudo", "systemctl", "restart", service])
        if r.returncode != 0:
            print("Не удалось перезапустить службу.", file=sys.stderr)
            return 1
        print("Служба перезапущена.")
    return 0

def list_usernames_by_prefix_from_password(cur, prefix: str) -> List[str]:
    """Возвращает список username, у которых есть атрибут Cleartext-Password и которые
    соответствуют заданному префиксу (с учётом настроек USE_PREFIX/PREFIX_POSITION)."""
    cur.execute(
        f"SELECT username FROM {TBL_RADCHECK} WHERE attribute='Cleartext-Password'"
    )
    rows = cur.fetchall()
    result: List[str] = []
    for (uname,) in rows:
        if matches_prefix(uname, prefix):
            result.append(uname)
    return result

def set_user_password(cur, username: str, new_password: Optional[str] = None) -> str:
    """Обновляет (или вставляет) Cleartext-Password для пользователя и возвращает пароль."""
    if new_password is None:
        new_password = random_password()
    cur.execute(
        f"SELECT id FROM {TBL_RADCHECK} WHERE username=%s AND attribute='Cleartext-Password' LIMIT 1",
        (username,),
    )
    row = cur.fetchone()
    if row:
        db_execute(
            cur,
            f"UPDATE {TBL_RADCHECK} SET value=%s WHERE username=%s AND attribute='Cleartext-Password'",
            (new_password, username),
        )
    else:
        db_execute(
            cur,
            f"INSERT INTO {TBL_RADCHECK} (username, attribute, op, value) VALUES (%s,'Cleartext-Password',':=',%s)",
            (username, new_password),
        )
    return new_password

def list_users_by_prefix(cur, prefix: str) -> List[str]:
    cur.execute(
        f"SELECT username FROM {TBL_RADCHECK} WHERE attribute='Cleartext-Password'"
    )
    rows = cur.fetchall()
    result: List[str] = []
    for (uname,) in rows:
        if matches_prefix(uname, prefix):
            result.append(uname)
    return result

def manage_menu():
    print("=== Управление пользователями по префиксам ===")
    if not PREFIXES and USE_PREFIX:
        print("В конфигурации нет префиксов. Запустите -config для настройки.")
    if not USE_PREFIX:
        print("Внимание: в конфигурации отключено использование префикса — фильтрация по префиксу не работает.")
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
                    print("  1) Показать пользователей по префиксу")
                    print("  2) Удалить пользователя по username")
                    print("  3) Сменить пароль у пользователя")
                    print("  4) Сменить пароли всем по префиксу")
                    print("  b) Назад к выбору префикса")
                    print("  q) Выход")
                    choice = input("Выбор: ").strip().lower()

                    if choice == "1":
                        users = list_users_by_prefix(cur, pref)
                        if not users:
                            print("Пользователи не найдены.")
                        else:
                            print(f"Найдено {len(users)} пользователей. Первые 50:")
                            for u in users[:50]:
                                print(f"  {u}")

                    elif choice == "2":
                        uname = input("Username для удаления: ").strip()
                        if uname:
                            delete_user_everywhere(cur, uname)
                            conn.commit()
                            print("Удалено (если существовал):", uname)

                    elif choice == "3":
                        uname = input("Username для смены пароля: ").strip()
                        if uname:
                            newp = set_user_password(cur, uname)
                            conn.commit()
                            print("Новый пароль:", newp)

                    elif choice == "4":
                        users = list_users_by_prefix(cur, pref)
                        if not users:
                            print("Пользователи не найдены.")
                        else:
                            print(f"Будут изменены пароли у {len(users)} пользователей. Подтвердить? (y/N)")
                            ans = input().strip().lower()
                            if ans in ("y", "yes"):
                                for u in users:
                                    set_user_password(cur, u)
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

def nas_menu():
    print("=== Управление NAS/policies (huntgroups + access) ===")
    cfg = load_config()
    policies = cfg.get("RADIUS_ACCESS_POLICIES") or []
    if not isinstance(policies, list):
        policies = []
    mode = str(cfg.get("RADIUS_FR_MODE", "virtual_server")).strip().lower()

    def show_policies():
        if not policies:
            print("Политики отсутствуют.")
            return
        print(f"Всего политик: {len(policies)}")
        for i, p in enumerate(policies, 1):
            print(f"{i}) prefix='{p.get('prefix','')}', hg='{p.get('huntgroup','')}', "
                  f"cidrs={len(p.get('cidrs',[]) or [])}, nasid={len(p.get('nas_identifier_regex',[]) or [])}, called={len(p.get('called_station_regex',[]) or [])}")

    def input_list(prompt_text: str, current: List[str]) -> List[str]:
        print(f"Текущее: {current if current else '[]'}")
        s = input(f"{prompt_text} (через запятую, пусто = оставить без изменений): ").strip()
        if s == "":
            return current
        return [x.strip() for x in s.split(",") if x.strip()]

    def edit_policy(idx: int):
        if idx < 0 or idx >= len(policies):
            print("Неверный номер.")
            return
        p = policies[idx]
        print(f"— Редактирование политики #{idx+1}")
        pref = input(f"Префикс [{p.get('prefix','')}]: ").strip() or p.get('prefix','')
        hg_def = p.get('huntgroup') or default_huntgroup_for_prefix(pref)
        hg = input(f"Huntgroup [{hg_def}]: ").strip() or hg_def
        cidrs = input_list("CIDR подсети NAS", p.get('cidrs', []) or [])
        nasid = input_list("Regex NAS-Identifier", p.get('nas_identifier_regex', []) or [])
        called = input_list("Regex Called-Station-Id", p.get('called_station_regex', []) or [])
        p.update({
            "prefix": pref,
            "huntgroup": hg,
            "cidrs": cidrs,
            "nas_identifier_regex": nasid,
            "called_station_regex": called,
        })
        policies[idx] = p

    def add_policy():
        pref = input("Префикс (например, office-): ").strip()
        if not pref:
            print("Префикс пустой — отмена.")
            return
        hg = input(f"Huntgroup [{default_huntgroup_for_prefix(pref)}]: ").strip() or default_huntgroup_for_prefix(pref)
        cidr_str = input("CIDR подсети NAS (через запятую) [0.0.0.0/32]: ").strip() or "0.0.0.0/32"
        cidrs = [c.strip() for c in cidr_str.split(",") if c.strip()]
        nasid_str = input("Regex NAS-Identifier (через запятую) [пропустить]: ").strip()
        nasid = [r.strip() for r in nasid_str.split(",") if r.strip()] if nasid_str else []
        called_str = input("Regex Called-Station-Id (через запятую) [пропустить]: ").strip()
        called = [r.strip() for r in called_str.split(",") if r.strip()] if called_str else []
        policies.append({
            "prefix": pref,
            "huntgroup": hg,
            "cidrs": cidrs,
            "nas_identifier_regex": nasid,
            "called_station_regex": called,
        })

    def delete_policy():
        if not policies:
            print("Список пуст.")
            return
        show_policies()
        try:
            i = int(input("Номер для удаления: ").strip()) - 1
        except ValueError:
            print("Некорректный ввод.")
            return
        if 0 <= i < len(policies):
            removed = policies.pop(i)
            print(f"Удалено: prefix='{removed.get('prefix','')}', hg='{removed.get('huntgroup','')}'")
        else:
            print("Неверный номер.")

    def rebuild_from_prefixes():
        pfxs = cfg.get("RADIUS_PREFIXES", []) if cfg.get("RADIUS_USE_PREFIX", True) else []
        if not pfxs:
            print("Префиксы не заданы или отключены.")
            return
        existing_keys = {(p.get('prefix'), p.get('huntgroup')) for p in policies if isinstance(p, dict)}
        added = 0
        for pref in pfxs:
            candidate = (pref, default_huntgroup_for_prefix(pref))
            if candidate not in existing_keys:
                policies.append({
                    "prefix": pref,
                    "huntgroup": candidate[1],
                    "cidrs": ["0.0.0.0/32"],
                    "nas_identifier_regex": [],
                    "called_station_regex": [],
                })
                added += 1
        print(f"Добавлено заготовок: {added}")

    def save_and_optionally_render():
        cfg["RADIUS_ACCESS_POLICIES"] = policies
        save_config(cfg)
        print(f"Сохранено в {CONFIG_FILE}")
        try:
            do_render = input("Сгенерировать конфиги FreeRADIUS сейчас? (y/N): ").strip().lower() in ("y","yes")
        except Exception:
            do_render = False
        if do_render:
            path = input("Каталог вывода (или '-' для консоли) [fr-conf]: ").strip() or "fr-conf"
            export_freeradius_config(cfg, path if path else None)

    def assign_nas_servers():
        # Назначение поля nas.server по политикам (виртуальный сервер = huntgroup)
        if mode != "virtual_server":
            print("Назначение NAS.server актуально только для режима 'virtual_server'.")
            return
        try:
            conn = pymysql.connect(
                host=cfg["RADIUS_DB_HOST"], port=int(cfg["RADIUS_DB_PORT"]), user=cfg["RADIUS_DB_USER"],
                password=cfg["RADIUS_DB_PASS"], database=cfg["RADIUS_DB_NAME"], autocommit=False,
                charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor
            )
        except Exception as e:
            print("Не удалось подключиться к БД:", e)
            return
        updated = 0
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, nasname, shortname, server FROM nas")
                rows = cur.fetchall() or []
                def ip_in_policy(ip: str, pol: Dict[str, Any]) -> bool:
                    try:
                        ipaddr = ipaddress.ip_address(ip)
                    except Exception:
                        return False
                    for net in pol.get("cidrs", []) or []:
                        try:
                            if ipaddr in ipaddress.ip_network(str(net), strict=False):
                                return True
                        except Exception:
                            pass
                    return False
                def shortname_match(sn: str, pol: Dict[str, Any]) -> bool:
                    for rx in pol.get("nas_identifier_regex", []) or []:
                        try:
                            if __import__("re").search(rx, sn or ""):
                                return True
                        except Exception:
                            pass
                    return False
                for r in rows:
                    target = None
                    for p in policies:
                        if ip_in_policy(str(r.get("nasname", "")), p) or shortname_match(str(r.get("shortname", "")), p):
                            target = p.get("huntgroup")
                            break
                    if target and r.get("server") != target:
                        print(f"NAS id={r['id']} {r['nasname']} shortname={r['shortname']} => server='{target}'")
                        try:
                            cur.execute("UPDATE nas SET server=%s WHERE id=%s", (target, r["id"]))
                            updated += 1
                        except Exception as e:
                            print("Ошибка обновления NAS:", e)
                conn.commit()
        finally:
            conn.close()
        print(f"Назначено записей: {updated}")

    while True:
        print("\nМеню:")
        print(" 1) Показать политики")
        print(" 2) Добавить политику")
        print(" 3) Редактировать политику")
        print(" 4) Удалить политику")
        print(" 5) Добавить заготовки по префиксам")
        print(" 6) Переключить режим ENFORCE (сейчас: %s)" % ("ON" if cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS") else "OFF"))
        print(" 7) Сохранить и сгенерировать конфиги")
        print(" 8) Показать NAS из БД")
        print(" 9) Массово назначить NAS.server по политикам")
        print(" q) Выход")
        choice = input("Выбор: ").strip().lower()
        if choice == "1":
            show_policies()
        elif choice == "2":
            add_policy()
        elif choice == "3":
            if not policies:
                print("Список пуст.")
                continue
            show_policies()
            try:
                idx = int(input("Номер для редактирования: ").strip()) - 1
                edit_policy(idx)
            except ValueError:
                print("Некорректный ввод.")
        elif choice == "4":
            delete_policy()
        elif choice == "5":
            rebuild_from_prefixes()
        elif choice == "6":
            cfg["RADIUS_ENFORCE_PREFIX_ACCESS"] = not bool(cfg.get("RADIUS_ENFORCE_PREFIX_ACCESS"))
            print("ENFORCE теперь:", "ON" if cfg["RADIUS_ENFORCE_PREFIX_ACCESS"] else "OFF")
        elif choice == "7":
            save_and_optionally_render()
        elif choice == "8":
            try:
                conn = pymysql.connect(
                    host=cfg["RADIUS_DB_HOST"], port=int(cfg["RADIUS_DB_PORT"]), user=cfg["RADIUS_DB_USER"],
                    password=cfg["RADIUS_DB_PASS"], database=cfg["RADIUS_DB_NAME"], autocommit=True,
                    charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor
                )
                with conn.cursor() as cur:
                    cur.execute("SELECT id, nasname, shortname, server FROM nas ORDER BY id LIMIT 100")
                    rows = cur.fetchall() or []
                    if not rows:
                        print("NAS не найдены.")
                    else:
                        for r in rows:
                            print(f"[{r['id']}] nasname={r['nasname']} shortname={r['shortname']} server={r['server']}")
            except Exception as e:
                print("Ошибка чтения NAS:", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        elif choice == "9":
            assign_nas_servers()
        elif choice == "q":
            return 0
        else:
            print("Неизвестная команда.")

def main():
    global DRY_RUN
    # Обработка ключа -config/--config
    if any(arg in ("-config", "--config") for arg in sys.argv[1:]):
        sys.exit(interactive_config())
    # Обработка ключа -nas/--nas (интерактивное управление политиками/NAS)
    if any(arg in ("-nas", "--nas") for arg in sys.argv[1:]):
        sys.exit(nas_menu())
    # Экспорт конфигов FreeRADIUS (huntgroups + authorize сниппет)
    if any(arg in ("-render-fr", "--render-fr") for arg in sys.argv[1:]):
        # Аргумент пути (необязательный). Пример: --render-fr /tmp/fr
        out_dir: Optional[str] = None
        for i, a in enumerate(sys.argv[1:], start=1):
            if a in ("-render-fr", "--render-fr"):
                if i < len(sys.argv)-0:
                    try:
                        cand = sys.argv[i+1]
                        if cand and not cand.startswith("-"):
                            out_dir = cand
                    except Exception:
                        pass
        sys.exit(export_freeradius_config(CFG, out_dir))
    # Импорт конфигов FreeRADIUS с проверкой и опциональным рестартом
    if any(arg in ("-import-fr", "--import-fr") for arg in sys.argv[1:]):
        restart = any(a in ("--restart", "-restart") for a in sys.argv[1:])
        sys.exit(import_freeradius_config(CFG, restart=restart))
    # Обработка ключа -manage/--manage
    if any(arg in ("-manage", "--manage") for arg in sys.argv[1:]):
        sys.exit(manage_menu())
    # Обработка ключа -schedule/--schedule (Debian cron)
    if any(arg in ("-schedule", "--schedule") for arg in sys.argv[1:]):
        sys.exit(schedule_menu())

    if USE_PREFIX:
        if not PREFIXES:
            print("ERROR: не задан ни один префикс. Укажите RADIUS_PREFIXES или RADIUS_PREFIX.", file=sys.stderr)
            sys.exit(2)
        iter_prefixes = PREFIXES
    else:
        # Если префиксы не используются, всё равно выполним создание хотя бы один раз
        iter_prefixes = PREFIXES if PREFIXES else [""]

    # DRY-RUN
    if any(arg in ("-n", "--dry-run") for arg in sys.argv[1:]) or str(os.getenv("RADIUS_DRY_RUN", "")).lower() in ("1","true","yes","on"):
        DRY_RUN = True

    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME,
            autocommit=False, charset="utf8mb4", cursorclass=pymysql.cursors.Cursor
        )
    except Exception as e:
        print("ERROR: не удалось подключиться к БД:", e, file=sys.stderr)
        sys.exit(2)

    created = []   # [(prefix, username, password)]
    rotated = []   # [(prefix, username, new_password)]

    try:
        with conn.cursor() as cur:
            # Для каждого префикса: если есть существующие — меняем пароли всем.
            # Если нет — создаём COUNT_PER_PREFIX новых.
            for pref in iter_prefixes:
                existing = list_usernames_by_prefix_from_password(cur, pref)
                if existing:
                    for uname in existing:
                        new_pass = set_user_password(cur, uname)
                        rotated.append((pref, uname, new_pass))
                    # Доукомплектуем при необходимости до COUNT_PER_PREFIX
                    if len(existing) < max(1, COUNT_PER_PREFIX):
                        for _ in range(max(1, COUNT_PER_PREFIX) - len(existing)):
                            u, p = create_user(cur, pref)
                            created.append((pref, u, p))
                else:
                    for _ in range(max(1, COUNT_PER_PREFIX)):
                        u, p = create_user(cur, pref)
                        created.append((pref, u, p))

        if DRY_RUN:
            conn.rollback()
            print("DRY-RUN: транзакция откатена, изменения не применены.")
        else:
            conn.commit()

    except Exception as e:
        conn.rollback()
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()

    # --- РЕЗЮМЕ ---
    # Резюме
    if created:
        print("=== Created users ===")
        for pref, u, p in created:
            print(f"[{pref}]")
            print(f"  Username  : {u}")
            print(f"  Password  : {p}")
    if rotated:
        print("\n=== Rotated passwords ===")
        for pref, u, p in rotated:
            print(f"[{pref}] {u}")
            print(f"  New Password: {p}")
    if not created and not rotated:
        print("Нет действий: не найдено подходящих префиксов и настроек.")

if __name__ == "__main__":
    main()
