# Radius Rotate

Утилита для массового создания аккаунтов и регулярной ротации паролей в FreeRADIUS/daloRADIUS с поддержкой генерации правил доступа (huntgroups + unlang) на основе префиксов логинов.

Ключевые идеи:
- Пароли меняются автоматически (при каждом запуске скрипта), пользователи не удаляются и срок действия (Expiration) не используется.
- Для разных зон/устройств можно выделить префиксы (например, `office-`) и сгенерировать конфигурацию FreeRADIUS, чтобы на «офисные» устройства пускать только с логинами, начинающимися с этого префикса.
- Вся конфигурация хранится в `config.json` (или задаётся переменными окружения), есть интерактивные мастера `-config` и `-nas`.

## Возможности

- Создание пользователей по префиксам: `username = <PREFIX><случайный хвост>`, `password = <случайный>`.
- Ротация паролей существующих пользователей по префиксу при каждом запуске.
- Доукомплектование недостающих аккаунтов до нужного количества на префикс.
- Опциональная привязка к группе (`radusergroup`) и заполнение `userinfo` (если таблица есть).
- Генерация фрагментов конфигурации FreeRADIUS: `huntgroups` и unlang‑сниппет для `authorize`.
- Интерактивный мастер `-config` (включая опрос по NAS/политикам) и редактор политик `-nas`.

## Требования

- Python 3.8+
- Библиотека: `pymysql`

Установка зависимостей:

```
pip install pymysql
```

## Быстрый старт

1) Настройте соединение с БД и базовые параметры:

```
python rotate.py -config
```

В процессе мастера можно сразу включить «Ограничение доступа по префиксам» и заполнить условия для NAS (CIDR/regex).

2) Сгенерируйте фрагменты FreeRADIUS (при желании мастер сам предложит это сделать):

```
python rotate.py --render-fr fr-conf
```

3) Запустите ротацию:

```
python rotate.py
```

При первом запуске для каждого префикса будут созданы аккаунты; при последующих — пароли у всех подходящих пользователей будут заменены, а недостающее количество дозаполнено.

## Конфигурация

Конфигурация хранится в `config.json`. Любой параметр можно переопределить переменными окружения (они приоритетнее). Путь к конфигу — через переменную `RADIUS_CONFIG_FILE`.

Основные параметры:

- `RADIUS_DB_HOST` (str): хост MySQL, по умолчанию `127.0.0.1`.
- `RADIUS_DB_PORT` (int): порт, по умолчанию `3306`.
- `RADIUS_DB_USER` / `RADIUS_DB_PASS` / `RADIUS_DB_NAME` (str): доступ к БД.
- `RADIUS_PREFIXES` (list | str): список префиксов (например, `["office-", "guest-"]` или строка через запятую).
- `RADIUS_USE_PREFIX` (bool): использовать ли префикс в имени пользователя.
- `RADIUS_PREFIX_POSITION` (start|end): позиция префикса в имени (`start`|`end`).
- `RADIUS_COUNT_PER_PREFIX` (int): требуемое число аккаунтов на префикс (>=1).
- `RADIUS_USERNAME_TAIL_LEN` (int): длина случайной части имени (без префикса).
- `RADIUS_PASSWORD_LEN` (int): длина пароля.
- `RADIUS_PASS_PUNCT` (str|null): набор разрешённой пунктуации для паролей; пусто/null — использовать стандартный `string.punctuation`.
- `RADIUS_ENABLE_GROUP` (bool) и `RADIUS_GROUP_NAME` (str): назначить группу через `radusergroup`.

Политики доступа (huntgroups + unlang):

- `RADIUS_ENFORCE_PREFIX_ACCESS` (bool): включить генерацию правил доступа для префиксов.
- `RADIUS_ACCESS_POLICIES` (array): список объектов вида:

```
{
  "prefix": "office-",
  "huntgroup": "office-devs",           // опционально; по умолчанию генерится из префикса
  "cidrs": ["10.0.0.0/24", "10.0.1.0/24"],
  "nas_identifier_regex": ["^office-.*$"],
  "called_station_regex": ["^OFFICE_SSID-.*$"]
}
```

Примечания:
- Если `RADIUS_ENFORCE_PREFIX_ACCESS=true`, но `RADIUS_ACCESS_POLICIES` пуст, мастер `-config` создаст заготовки по каждому префиксу с безопасным плейсхолдером `0.0.0.0/32`.
- CIDR /8,/16,/24 конвертируются в regex по октетам; /32 — в точное совпадение IP. Сложные маски деградируют до адреса сети (можно отредактировать вручную).
- Для «неизвестных NAS» используйте правила по `NAS-Identifier`/`Called-Station-Id` — новые устройства, именованные по шаблону, автоматически попадут в нужный huntgroup.

## Генерация конфигов FreeRADIUS

Сгенерировать в каталог:

```
python rotate.py --render-fr fr-conf
```

Будут созданы:
- `fr-conf/huntgroups.radius-rotate` — фрагмент для `/etc/freeradius/3.0/huntgroups`.
- `fr-conf/authorize.radius-rotate.snippet` — фрагмент для `sites-enabled/default` (секция `authorize`).

Как применить на FreeRADIUS 3.x:
- Убедитесь, что модуль `preprocess` включён в `authorize`.
- Добавьте строки из `huntgroups.radius-rotate` в `/etc/freeradius/3.0/huntgroups`.
- Вставьте `authorize.radius-rotate.snippet` в `sites-enabled/default` сразу после `preprocess`.
- Перезапустите службу: `systemctl restart freeradius`.

## CLI

- `-config` / `--config` — интерактивная настройка (подключение к БД, префиксы, группы, политики доступа) и опциональная генерация конфигов FR.
- `-nas` / `--nas` — интерактивный редактор политик доступа/NAS (список, добавление, редактирование, удаление, автодобавление заготовок, генерация файлов FR).
- `-render-fr [DIR|-]` — вывести фрагменты FR в каталог `DIR` или в консоль (`-`).
- `-import-fr [--restart]` — импортировать конфигурацию прямо в FreeRADIUS под `sudo` с проверкой (`freeradius -XC`). При `--restart` перезапускает службу (`systemctl restart <service>`).
- `-manage` — меню по префиксам (просмотр пользователей, удаление, смена пароля одному/всем по префиксу).
- `-schedule` — помощник для установки периодического запуска в Debian cron.
- `-n` / `--dry-run` — «репетиция»: выполняет все вычисления и SQL‑операции без записи в БД (транзакция будет откатена).

## Замечания по безопасности

- `config.json` содержит доступ к БД — ограничьте права на файл.
- Скрипт хранит пароли пользователей в `radcheck` с `Cleartext-Password` (требуется для PAP). Убедитесь, что ваш pipeline и аудит соответствуют политикам безопасности.

## Параметры для импорта в FreeRADIUS (необязательно)

- `RADIUS_FR_BASE` (str): база конфигурации FR, по умолчанию `/etc/freeradius/3.0` (Debian 3.x).
- `RADIUS_FR_HUNTGROUPS_PATH` (str|null): путь к файлу `huntgroups`. Если пусто — используется `${BASE}/mods-config/preprocess/huntgroups`.
- `RADIUS_FR_SITE_DEFAULT_PATH` (str|null): путь к `sites-enabled/default`. Если пусто — `${BASE}/sites-enabled/default`.
- `RADIUS_FR_SERVICE` (str): имя systemd‑сервиса, по умолчанию `freeradius`.

## Примеры

Создать 2 аккаунта на префикс `office-` и включить ограничение доступа для офисных NAS:

```json
{
  "RADIUS_DB_HOST": "127.0.0.1",
  "RADIUS_DB_PORT": 3306,
  "RADIUS_DB_USER": "radius",
  "RADIUS_DB_PASS": "secret",
  "RADIUS_DB_NAME": "radiusdb",
  "RADIUS_PREFIXES": ["office-"],
  "RADIUS_COUNT_PER_PREFIX": 2,
  "RADIUS_ENFORCE_PREFIX_ACCESS": true,
  "RADIUS_ACCESS_POLICIES": [
    {
      "prefix": "office-",
      "huntgroup": "office-devs",
      "cidrs": ["10.0.0.0/24"],
      "nas_identifier_regex": ["^office-.*$"]
    }
  ]
}
```

Далее:

```
python rotate.py --render-fr fr-conf
python rotate.py
```
