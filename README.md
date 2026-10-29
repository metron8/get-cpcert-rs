# get-cpcert-rs

[![CI](https://github.com/metron8/get-cpcert-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/metron8/get-cpcert-rs/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.75-blue)](https://www.rust-lang.org)

Утилита на Rust, извлекающая сертификат и закрытый ключ из:

- **Контейнера КриптоПро 4/5** — директория `*.000/` с файлами `header.key`, `primary.key`, `masks.key`.
- **PFX/PKCS#12** — файл `*.pfx` или `*.p12`, экспортированный КриптоПро CSP (`cryptcp -copycert -dest -df`).

Форматы ключей: ГОСТ Р 34.10-2001, ГОСТ Р 34.10-2012/256, ГОСТ Р 34.10-2012/512. Результат — PEM-файл (`CERTIFICATE` + `PRIVATE KEY` в PKCS#8), совместимый с OpenSSL 1.1.1+ с подключённым gost-engine.

Это переписанная на Rust версия [kov-serg/get-cpcert](https://github.com/kov-serg/get-cpcert) (GPL-2.0). Лицензия наследуется. Реализация полностью независимая — повторён только протокол (формат контейнера/PFX и криптопримитивы), исходный код написан с нуля на Rust.

## Использование

CLI автоматически определяет тип входа по пути: директория → контейнер, файл → PFX.

### Контейнер (директория)

```bash
# Пароль через stdin (рекомендуется):
get-cpcert /path/to/MyKey.000 > cert.pem

# Пароль из файла:
get-cpcert /path/to/MyKey.000 --password-file ./pwd.txt > cert.pem

# Пароль аргументом (видно в `ps`, только для скриптов в защищённой среде):
get-cpcert /path/to/MyKey.000 -p hunter2 > cert.pem

# Сразу в файл:
get-cpcert /path/to/MyKey.000 -o cert.pem
```

Контейнер — это директория (обычно `что-то.000/`), содержащая `header.key`, `primary.key` (или `primary2.key`), `masks.key` (или `masks2.key`), `name.key`, `kek.opq`. Утилите нужны первые три. Если основных `primary.key`/`masks.key` нет, автоматически подхватываются варианты с суффиксом `2` (бывает в более новых версиях КриптоПро).

Если сертификат хранится отдельно и возникает `Missing field in container: header.key: [5] certificate`, передайте его через `--cert`:

```bash
get-cpcert /path/to/MyKey.000 --cert /path/to/certificate.cer -o bundle.pem
```

Принимается один X.509-сертификат в DER или PEM. Внешний сертификат имеет приоритет над встроенным. Перед выдачей результата проверяются алгоритм, поддерживаемая кривая и совпадение полного публичного ключа сертификата с извлечённым закрытым ключом. Проверка цепочки доверия и срока действия не выполняется. При ошибке извлечения выходной файл не записывается. Результат содержит `CERTIFICATE` и незашифрованный `PRIVATE KEY`. Параметр `--cert` применим только к директории контейнера и несовместим с `--inspect`.

### PFX / PKCS#12

```bash
# Тот же CLI — путь к файлу .pfx или .p12:
get-cpcert /path/to/cert.pfx -p hunter2 > cert.pem

# Без пароля (КриптоПро при экспорте позволяет задать пустой пароль PFX):
get-cpcert /path/to/cert.pfx -p '' -o cert.pem
```

Пароль PFX задаётся в момент экспорта в КриптоПро CSP и **может отличаться** от пароля контейнера-источника. Если экспорт был без пароля — передавайте `-p ''`.

### Диагностика `--inspect`

Когда расшифровка падает с непонятной ошибкой, посмотрите внутрь файла **без пароля**:

```bash
get-cpcert --inspect /path/to/cert.pfx
```

Печатает структурный отчёт: версия PFX, тип authSafe, список ContentInfo'ов, для каждого SafeBag — его тип, размер, какая PBE-схема использована для шифрования (со своими salt и iter), и информацию о MAC. OID'ы выводятся со своими «человеческими» именами. Никакая расшифровка не происходит, пароль не нужен.

Пример вывода:

```
PFX inspection report
  version           : Some(3)
  authSafe type     : 1.2.840.113549.1.7.1 (id-data (PKCS#7))
  authSafe size     : 1039 bytes
  ContentInfos      : 2
    [0] type        : 1.2.840.113549.1.7.1 (id-data (PKCS#7))
        bags      : 1
          [0] 1.2.840.113549.1.12.10.1.2 (pkcs8ShroudedKeyBag) (180 bytes)
              PBE  : 1.2.840.113549.1.12.1.80 (CryptoPro PBE (.80) — proprietary GOST key transport)
              salt : E0BC484885A96EEAC759D2949D450465
              iter : 2000
              ct   : 139 bytes
    [1] type        : 1.2.840.113549.1.7.6 (id-encryptedData (PKCS#7))
        encrypted
          PBE       : 1.2.840.113549.1.12.1.6 (pbeWithSHAAnd40BitRC2-CBC)
          salt      : 08C355881F352C409308205125D0FE8A
          iter      : 2000
          ct size   : 584 bytes
  MacData
    digest          : 1.3.14.3.2.26 (id-sha1)
    salt            : B79BE1AB2502F02A08DFCFA7D86796597E4CA476
    iter            : 2000
    digest value    : 394A5521712DB9F4B20CA7ADB0ABB7232DCA76EE
```

Если столкнётесь с неподдерживаемым форматом — пришлите вывод `--inspect`, по нему сразу видно, какую PBE/bag нужно добавить.

### Использование как библиотека

```rust
use get_cpcert::{extract, extract_from_pfx};

// Контейнер:
let pem = extract(std::path::Path::new("MyKey.000"), "password")?;

// PFX из памяти:
let pfx_bytes = std::fs::read("cert.pfx")?;
let pem = extract_from_pfx(&pfx_bytes, "password")?;
```

## Сборка

```bash
cargo build --release -p get-cpcert
# бинарник: target/release/get-cpcert
```

Минимальная версия Rust: 1.75. Чистые Rust-зависимости, без C-библиотек, без линковки против OpenSSL.

## WebAssembly

Проект — workspace. Параллельно с CLI собирается WASM-обёртка `get-cpcert-wasm` для использования в браузере (контейнер обрабатывается в браузере, ключи никуда не уходят):

```bash
wasm-pack build wasm --target web --release
# артефакты: wasm/pkg/*.wasm, *.js, *.d.ts

# Демо в браузере:
cp -r wasm/pkg wasm/demo/pkg
python3 -m http.server -d wasm/demo 8000
# открыть http://localhost:8000
```

Подробности и JS API — см. `wasm/README.md`.

## Что поддерживается

### Контейнеры

- Алгоритм по OID из `header.key`:
  - `1.2.643.2.2.30.1` → ГОСТ Р 34.10-2001
  - `1.2.643.7.1.1.2.2` → ГОСТ Р 34.10-2012 (256 бит)
  - `1.2.643.7.1.1.2.3` → ГОСТ Р 34.10-2012 (512 бит)
- Кривые: CryptoPro_XchA_ParamSet (для 2001/2012-256), tc26_512_paramSetA (для 2012-512).
- Контейнеры, защищённые паролем, и контейнеры без пароля (KDF использует 2 итерации вместо 2000).

### PFX / PKCS#12

Три PBE-схемы:

| OID | Где встречается | Реализация |
|---|---|---|
| `1.2.840.113549.1.12.1.80` | `pkcs8ShroudedKeyBag` в экспортах КриптоПро CSP | Собственный KDF КриптоПро (итеративный Gost94CryptoPro) + GOST 28147-89 CFB + второй уровень key wrap по RFC 4357/7836 (`KDF_GOSTR3411_2012_256` для диверсификации, ECB-расшифровка CEK). |
| `1.2.840.113549.1.12.1.6` | `certBag` в экспортах КриптоПро CSP | Стандартный PKCS#12 PBE-SHA1-40BitRC2-CBC (PKCS#12 v1 KDF с SHA-1, RC2 с 40-битным эффективным ключом, CBC). |
| `1.2.840.113549.1.12.1.3` | Альтернативный wrapper в КриптоПро/non-CryptoPro PFX | Стандартный PKCS#12 PBE-SHA1-3-Key-TripleDES-CBC (PKCS#12 v1 KDF с SHA-1, 3DES EDE3 в CBC). |
| `1.2.840.113549.1.5.13` | Standards-compliant ГОСТ PFX от других тулзов | PBES2 с PBKDF2-HMAC-Streebog256 + GOST 28147-89 CFB (TC26-Z и CryptoPro-A S-boxes). |

Спецификация формата КриптоПро `.80` восстановлена по референс-реализациям [li0ard/cpfx](https://github.com/li0ard/cpfx) (Python) и RFC 7836 §4.5.

## Архитектура

| Модуль | Что делает |
| --- | --- |
| `asn1` | Минимальный BER/DER парсер (поддерживает indefinite-length). |
| `container` | Чтение `header.key`, `primary.key`, `masks.key`, извлечение полей. |
| `kdf` | KDF КриптоПро для контейнеров (варианты ГОСТ-2001 на Gost94 и ГОСТ-2012 на Streebog-256). |
| `gost28147` | Блочный шифр ГОСТ 28147-89 (ECB/CFB) с переключаемыми S-боксами (CryptoPro A и TC26 Z). |
| `gost_ec` | Кривые ГОСТ Р 34.10, точки, скалярное умножение через `num-bigint-dig`. |
| `pem_out` | Шаблоны PKCS#8 PrivateKeyInfo и сборка финального PEM. |
| `pfx` | PKCS#12 импортёр: PFX-парсер, CryptoPro PBE `.80`, PBE-SHA1-RC2-40, PBES2/PBKDF2-HMAC-Streebog, PKCS#12 v1 KDF, RFC 7836 `KDF_GOSTR3411_2012_256`. |
| `lib.rs::extract` / `extract_from_pfx` | Точки входа: оркестрация двух пайплайнов. |
| `main.rs` | CLI с автоопределением directory vs file. |

## Алгоритм извлечения

### Из контейнера

1. Распарсить `header.key` → определить OID алгоритма, получить 8 байт публичного ключа (`pub8`) и сам сертификат.
2. Из `primary.key` достать зашифрованный закрытый ключ.
3. Из `masks.key` достать маску и 12-байтную соль.
4. Вывести симметричный ключ KDF КриптоПро (`H((current⊕0x36)||salt_pass||(current⊕0x5C)||salt_pass)` с константой `"DENEFH028.760246785.IUEFHWUIO.EF"`).
5. Расшифровать `primary.key` ГОСТ 28147-89 (ECB), развернуть в big-endian → `key_with_mask`.
6. Снять маску: `raw_secret = key_with_mask · mask⁻¹ (mod q)`.
7. Проверить: `Q = raw_secret · G`, первые 8 байт `Q.x` в little-endian должны совпасть с `pub8` — иначе пароль неверный.
8. Вставить `raw_secret` в PKCS#8 шаблон, сформировать PEM-бандл.

### Из PFX (формат КриптоПро CSP)

1. Распарсить PFX → найти AuthenticatedSafe → перебрать ContentInfo'ы.
2. **certBag** (`id-encryptedData` с PBE-SHA1-RC2-40-CBC):
   - PKCS#12 v1 KDF (SHA-1) → 5-байтный ключ RC2 (40 эффективных бит) и 8-байтный IV.
   - RC2-CBC-расшифровка → SafeContents → certBag → x509Certificate в OCTET STRING.
3. **pkcs8ShroudedKeyBag** (OID `.80`):
   - `KEY₀ = UTF-16LE(password)`; `KEYᵢ₊₁ = Gost94CryptoPro(KEYᵢ ‖ salt ‖ u16be(i))` за `iter` итераций.
   - GOST 28147-89 CFB-расшифровка (IV = первые 8 байт salt, sbox CryptoPro-A) → CPBlob.
   - В `CPBlob.value` пропустить 16-байтный префикс, прочитать CPExportBlob: UKM, encrypted CEK, MAC, algtype.
   - `KEKₑ = HMAC-Streebog256(KEY, 0x01 ‖ 0x26BDB878 ‖ 0x00 ‖ UKM ‖ 0x01 ‖ 0x00)` (RFC 7836 §4.5 с CryptoPro-меткой диверсификации).
   - GOST 28147-89 ECB-расшифровка `cek_enc` с `KEKₑ` → raw scalar (32/64 байта по `algtype`).
   - Упаковка scalar в PKCS#8 через те же шаблоны, что и для контейнера → байт-в-байт идентичный вывод.

## Замечания о безопасности

- Все секреты (ключ из пароля, расшифрованный закрытый ключ) затираются `zeroize` после использования.
- EC-арифметика в `gost_ec` **не constant-time**. Этого достаточно для оффлайн-извлечения собственного ключа, но не используйте этот модуль для рантайм-подписи в продакшене.
- Эту утилиту имеет смысл запускать только над *своим* контейнером. Извлечение закрытого ключа из чужого носителя без разрешения владельца — нарушение закона.

## Тестирование

```bash
cargo test --release
```

Прогоняется 43 теста по пяти пластам:

1. **Криптопримитивы** (хеши, шифр, EC): известные тестовые векторы (Streebog-256 из RFC 6986, ГОСТ Р 34.11-94/CryptoPro), round-trip ГОСТ 28147-89 (ECB и CFB) на обоих наборах S-boxes, корректность параметров кривых (`q·G = ∞`, базовая точка на кривой), ассоциативность сложения, дистрибутивность скалярного умножения.

2. **Парсер ASN.1**: примитивные/составные теги, длинные формы длины, indefinite-length, OID-декодирование, реакция на обрезанные данные.

3. **PFX-примитивы**: PKCS#12 v1 KDF — известный SHA-1 test vector ("smeg" → 8AAAE6...), детерминизм PBKDF2-HMAC-Streebog256, prefix-стабильность при разной выходной длине, BER/DER reencode round-trip.

4. **Синтетические end-to-end** (`tests/synthetic.rs`, `tests/synthetic_pfx.rs`):
   - Контейнер: собрать минимальный валидный GOST-2012-256 контейнер с известным приватным ключом, прогнать через `extract`, сверить со входом.
   - PFX (PBES2): собрать стандартный PFX с PBES2/PBKDF2-HMAC-Streebog256/GOST 28147 CFB, прогнать через `extract_from_pfx`, сверить cert+key.
   - Тесты на неверный пароль проверяют, что мы аккуратно завершаемся с `InvalidPassword` вместо выдачи мусора.

5. **Интеграция против реальных файлов** (`tests/integration.rs`, `tests/integration_pfx.rs`):
   - Тест-харнесс ищет контейнеры в `tests/samples/<name>/` и PFX в `tests/samples_pfx/<name>/`, сравнивает наш PEM-вывод с `expected.pem` побайтово.
   - В репозитории:
     ```
     контейнеры:
       [g2001]            OK   GOST R 34.10-2001
       [g2012256]         OK   GOST R 34.10-2012/256
       [g2012256_alt]     OK   тот же ключ, другой контейнер
       [g2012256_padded]  OK   файлы дополнены 0xFF
       [g2012512]         OK   GOST R 34.10-2012/512
       [test_app_cert]    OK   реальный экспорт КриптоПро CSP, пароль "123"
     PFX:
       [test_cert]        OK   тот же ключ, что и test_app_cert, экспорт КриптоПро в .pfx (пароль пустой)
     ```
   - Все дают **байт-в-байт идентичный** PEM по сравнению с эталоном оригинальной C-утилиты. Совпадение `test_cert.pfx` с `test_app_cert/` (тот же ключ через два разных пути) валидирует корректность обоих пайплайнов.

## Что осталось доделать

- [ ] Опциональная поддержка контейнеров с TLS-only кривыми (paramSetB/C/D), сейчас захардкожены только XchA и 512_A.
- [ ] Перейти на constant-time EC, если кто-то захочет использовать модули как библиотеку для подписания (для извлечения собственного ключа в оффлайне это не критично).
- [ ] Полная верификация HMAC MacData в PFX (сейчас неверный пароль ловится sanity-check'ом расшифрованного PKCS#8 — работает, но менее явно).
- [ ] Проверить совместимость PFX-импортёра с экспортами других CSP (ViPNet, Signal-COM), если попадутся образцы.

## Благодарности

- [kov-serg/get-cpcert](https://github.com/kov-serg/get-cpcert) — оригинальная C-утилита, основа для портирования контейнерного пути.
- [li0ard/cpfx](https://github.com/li0ard/cpfx) — Python-реализация, по которой восстановлен формат КриптоПро PBE `1.2.840.113549.1.12.1.80`.
- [pygost](http://www.pygost.cypherpunks.ru/) — чистая Python-реализация ГОСТ-примитивов, использована для кросс-проверки на этапе разработки.
