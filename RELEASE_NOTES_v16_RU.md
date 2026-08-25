# METAL_CRYPTO_TOOLKIT v16.0.1

v16 — крупнейшее функциональное обновление Metal-тулкита. В нём появились
общие проверяемые планировщик, память и статистика, завершены несколько
форматов кошельков, добавлены новые GPU-режимы поиска и восстановления, а
оптимизированные BSGS и Kangaroo из v15 полностью сохранены.

## Хот-фикс v16.0.1 для Tahoe/M1 pipeline

- Три проблемные специализации pipeline заранее скомпилированы в Metal binary
  archive Tahoe 26: compressed-BIP32 `workerHmac_seq`, BIP38 non-EC
  `workerBip38Grouped` и BIP38 EC-multiply `workerBip38Grouped`.
- В бинарник встроены нативные payload для всех 11 Apple Silicon GPU slices,
  поддерживаемых translator, включая варианты M1/Apple7 `applegpu_g13*`.
  Точные совпадения используют `MTLComputePipelineDescriptor.binaryArchives`
  и не входят в аварийный путь JIT-компиляции первого pipeline.
- Существующий metallib AIR 2.6/macOS 14 остаётся fallback для всех остальных
  pipeline и для archive miss на другой версии Metal runtime.
- Steady-state работа ядер и dispatch не изменены. Архив добавляет около 48 МБ
  к бинарнику; все три strict archive-hit прошли на M4 Max. Прямое
  подтверждение на M1 ожидается от автора issue.

## Изменение AIR-совместимости в v16

- Встроенная Metal-библиотека теперь собирается для macOS 14 и AIR 2.6, а
  host-executable по-прежнему требует macOS 15.0 или новее.
- Это устраняет завершение `MTLCompilerService` с ошибкой
  `XPC_ERROR_CONNECTION_INTERRUPTED` при первой компиляции pipeline на
  GPU M1/Apple7. Поведение CLI и логика ядер не изменены.

## Главное

- Новые GPU-режимы: `-keyrepair`, `-nonce`, `-vanity`, `-create2`, `-hdpath`,
  `-warpwallet`, `-substratewallet`, `-copaywallet`, `-terrawallet`,
  `-bitshareswallet`, `-yoroiwallet`, `-monero`, `-monerowallet`,
  `-algorand`, `-stronghold`, `-chia`.
- Завершённые режимы и расширения: точный BIP38 non-EC/EC-multiply,
  `-priv -hamming`, `-mnemonic -scramble`, исторические профили `-brain`,
  восстановление SLIP-39, aezeed и ETH2 validator.
- Общий Apple-arm64 backend BLS12-381 используется ETH2 и Chia.
- BIP38 non-EC и EC-multiply используют изолированное grouped Metal-ядро без
  ресурсного влияния расширенного Substrate/Cardano wallet-контура.
- Независимые BIP38 KDF-группы объединяются в ограниченный памятью запуск,
  поэтому доступные scrypt-lanes работают параллельно, а не отдельными
  последовательными command buffers.
- Новые wallet-режимы используют checked U256/mixed-radix планирование,
  ограниченную unified memory, потоковые targets/artifacts и полную
  независимую проверку результата.
- Единственным потоком живой статистики остаётся `SpeedThreadFunc`.
  Количество целей никогда не используется как искусственный множитель.
- Основной бинарник содержит встроенную Metal-библиотеку и требует Apple
  Silicon с macOS 15.0 или новее.

## Итоги принятия волн

Каждая production-волна прошла точные CPU/reference ↔ Metal проверки,
malformed и boundary cases, собственные mode-controls, а также существующие
контроли private-key и P2WSH. Проверка M3 намеренно пропущена по решению
проекта.

| Волна | Production-результат | Решение по производительности |
|---:|---|---|
| 0 | Общие progress, memory и checked scheduling | Инфраструктурная регрессия пройдена |
| 1 | Точный BIP38 non-EC и EC-multiply | Принят memory-derived resident tuning |
| 2 | Checksum-first key repair | Принята host Base58 prefix-state оптимизация |
| 3 | Восстановление ECDSA и BIP340 nonce | Принят group-8 point batching |
| 4 | Multi-network vanity generation | Приняты intra-thread walk и depth 8 |
| 5 | Ethereum CREATE2 | Сохранён точный baseline 128 threads; rewrites отклонены |
| 6 | Поиск BIP32 HD path | Приняты root-public reuse и grid 256 threads |
| 7 | Точный Hamming-поиск привата | Сохранён точный baseline; rewrites отклонены |
| 8 | Перестановки BIP39 mnemonic | Принят three-limb hardware small-division |
| 9 | WarpWallet profile engine | Принят точный потоковый baseline |
| 10 | Brainwallet profiles/rules/combinators | Принят точный потоковый baseline |
| 11 | Восстановление Substrate keyring | Принят точный authenticated baseline |
| 12 | Восстановление Copay/BitPay SJCL | Принят shared AES round-key путь |
| 13 | Восстановление Terra Station legacy export | Принят точный authenticated baseline |
| 14 | Восстановление BitShares 0.x exported keys | Принят точный authenticated baseline |
| 15 | Восстановление Yoroi/EMIP-3 | Принят точный authenticated baseline |
| 16 | Monero mnemonic и Polyseed | Принят точный target-verified baseline |
| 17 | Восстановление Monero `.keys` | Принят точный CryptoNight/ChaCha baseline |
| 18 | Восстановление Algorand mnemonic | Принят fused resident-target путь |
| 19 | Восстановление SLIP-39 | Fused path: +9,14%/+9,57% |
| 20 | Восстановление LND aezeed | Memory-derived residency: +38,39%/+38,17% |
| 21 | Восстановление Stronghold v2 | Argon2 address-block reuse: около +100%/+97,8% |
| 22 | Общий backend BLS12-381 | arm64 assembly: +535,54%/+536,49% |
| 23 | Восстановление ETH2 validator | Metal KDF pipeline: +3214,38%/+3212,28% |
| 24 | Восстановление Chia | Metal плюс parallel BLS: +72,87%/+72,71% |
| 25 | Регрессия, изоляция BIP38 и упаковка v16 | BIP38 grouped concurrency: +93,84%/+93,70% |

Проценты сравнивают каждого принятого кандидата с обеими окружающими группами
A1/A2 по симметричному benchmark gate проекта. Для новых режимов без прежнего
production entry point использовалась независимая reference-реализация.

Gate BIP38 в Волне 25 использовал по 11 exact-запусков A1/B/A2. Медианы wall
time составили 9,948247 с, 5,132319 с и 9,941461 с; population CV — 0,044%,
0,123% и 0,106%. Все 33 запуска восстановили оба официальных non-EC вектора
с одинаковым SHA-256 результата.

## Совместимость и ограничения

- Совместимость CLI существующих режимов сохранена.
- BSGS и Kangaroo сохраняют прежнюю семантику `GStep/s`/`EqKey/s` и
  `Jump/s`/`EqKey/s`.
- Поддержка полной 256-битной арифметики не делает полный перебор 256 бит
  практически выполнимым.
- Режимы восстановления выводят результат только после полной
  криптографической проверки.
- Используйте тулкит только для ключей, кошельков и данных, которыми вы
  владеете либо которые вам явно разрешено восстанавливать.

## Файлы выпуска

- `METAL_CRYPTO_TOOLKIT-v16.0.1-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-v16.0.1-macos-arm64.tar.gz.sha256`
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz.sha256`

Tools-архивы не изменились с v16 и повторно в выпуск v16.0.1 не загружаются.

До распаковки проверьте каждый архив командой
`shasum -a 256 -c FILE.sha256`.
