from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import csv
import os
import shutil
import sys
from collections import Counter
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


DESKTOP = Path(_case_value('ae6d6877603b6a945206'))
ENC_ROOT = DESKTOP / "Зашифрованные файлы"
DEC_ROOT = DESKTOP / "Восстановленные файлы"
BUNDLE = DESKTOP / "Набор_для_анализа_шифрования"
EXT = ".xzg9VRelb"

PAIR_TOTAL_LIMIT = 115 * 1024 * 1024
PAIR_MIN_FILES = 200
PAIR_MAX_FILES = 300
MEDIA_LIMIT = 280 * 1024 * 1024

MEDIA_EXTS = {".jpg", ".jpeg", ".jfif", ".png", ".webp", ".mp4", ".mov", ".m4v", ".dav", ".lrv", ".thm"}


def out_for(enc: Path) -> Path:
    return DEC_ROOT / Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def copy_tree_file(src: Path, dst_root: Path, rel: Path) -> Path:
    dst = dst_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def select_pair_group(groups: dict[str, list[lr.EncryptedFile]]) -> tuple[str, list[lr.EncryptedFile]]:
    candidates = []
    for kek, files in groups.items():
        recovered = []
        for item in files:
            enc = Path(item.path)
            dec = out_for(enc)
            if not dec.exists() or not dec.is_file():
                continue
            try:
                if dec.stat().st_size <= 0:
                    continue
                recovered.append(item)
            except OSError:
                continue
        if len(recovered) < PAIR_MIN_FILES:
            continue
        exts = Counter(Path(item.original_name).suffix.lower() for item in recovered)
        diversity = len(exts)
        smallest = sorted(recovered, key=lambda it: Path(it.path).stat().st_size + out_for(Path(it.path)).stat().st_size)
        fit = []
        total = 0
        for item in smallest:
            pair_size = Path(item.path).stat().st_size + out_for(Path(item.path)).stat().st_size
            if total + pair_size > PAIR_TOTAL_LIMIT and len(fit) >= PAIR_MIN_FILES:
                break
            if total + pair_size <= PAIR_TOTAL_LIMIT:
                fit.append(item)
                total += pair_size
        if len(fit) < PAIR_MIN_FILES:
            continue
        candidates.append((diversity, len(fit), -abs(total - PAIR_TOTAL_LIMIT), kek, recovered))
    if not candidates:
        raise RuntimeError("No recovered group has enough files")
    candidates.sort(reverse=True)
    return candidates[0][3], candidates[0][4]


def balanced_pair_sample(items: list[lr.EncryptedFile]) -> list[lr.EncryptedFile]:
    buckets: dict[str, list[lr.EncryptedFile]] = {}
    for item in items:
        ext = Path(item.original_name).suffix.lower() or "<none>"
        buckets.setdefault(ext, []).append(item)
    for bucket in buckets.values():
        bucket.sort(key=lambda it: Path(it.path).stat().st_size + out_for(Path(it.path)).stat().st_size)

    selected: list[lr.EncryptedFile] = []
    total = 0
    # First pass: take one or more small files from each extension for diversity.
    while len(selected) < PAIR_MAX_FILES and total < PAIR_TOTAL_LIMIT:
        progressed = False
        for ext in sorted(buckets, key=lambda e: (len(selected), -len(buckets[e]), e)):
            bucket = buckets[ext]
            if not bucket:
                continue
            item = bucket.pop(0)
            pair_size = Path(item.path).stat().st_size + out_for(Path(item.path)).stat().st_size
            if total + pair_size > PAIR_TOTAL_LIMIT:
                continue
            selected.append(item)
            total += pair_size
            progressed = True
            if len(selected) >= PAIR_MAX_FILES:
                break
        if not progressed:
            break
    # Second pass: fill with the smallest remaining pairs while staying under cap.
    leftovers = [it for bucket in buckets.values() for it in bucket]
    leftovers.sort(key=lambda it: Path(it.path).stat().st_size + out_for(Path(it.path)).stat().st_size)
    for item in leftovers:
        if len(selected) >= PAIR_MAX_FILES:
            break
        pair_size = Path(item.path).stat().st_size + out_for(Path(item.path)).stat().st_size
        if total + pair_size > PAIR_TOTAL_LIMIT:
            if len(selected) >= PAIR_MIN_FILES:
                break
            continue
        selected.append(item)
        total += pair_size
    return selected


def select_unrecovered_media(groups: dict[str, list[lr.EncryptedFile]]) -> list[lr.EncryptedFile]:
    rows = []
    for kek, files in groups.items():
        for item in files:
            enc = Path(item.path)
            rel_no_ext = Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])
            if rel_no_ext.suffix.lower() not in MEDIA_EXTS:
                continue
            if out_for(enc).exists():
                continue
            size = enc.stat().st_size
            rows.append((kek, rel_no_ext.suffix.lower(), size, item))

    # Prefer a compact mixed sample: nearest gaps first are not available here, so
    # mix extensions and KEKs while staying under the requested size cap.
    by_ext: dict[str, list[tuple[str, int, lr.EncryptedFile]]] = {}
    for kek, ext, size, item in rows:
        by_ext.setdefault(ext, []).append((kek, size, item))
    for ext_rows in by_ext.values():
        ext_rows.sort(key=lambda x: x[1])

    selected = []
    total = 0
    while total < MEDIA_LIMIT:
        progressed = False
        for ext in sorted(by_ext):
            bucket = by_ext[ext]
            if not bucket:
                continue
            kek, size, item = bucket.pop(len(bucket) // 2)
            if selected and total + size > MEDIA_LIMIT:
                continue
            selected.append(item)
            total += size
            progressed = True
            if total >= MEDIA_LIMIT:
                break
        if not progressed:
            break
    return selected


def main() -> int:
    if BUNDLE.exists():
        shutil.rmtree(BUNDLE)
    BUNDLE.mkdir(parents=True, exist_ok=True)
    pairs_enc = BUNDLE / "01_пары_один_поток" / "encrypted"
    pairs_dec = BUNDLE / "01_пары_один_поток" / "decrypted"
    media_bad = BUNDLE / "02_невосстановленные_фото_видео" / "encrypted"
    video_later = BUNDLE / "03_видео_позже"
    for p in (pairs_enc, pairs_dec, media_bad, video_later):
        p.mkdir(parents=True, exist_ok=True)

    groups, scanned, skipped = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    kek, recovered_items = select_pair_group(groups)
    pair_items = balanced_pair_sample(recovered_items)

    pair_rows = []
    for item in pair_items:
        enc = Path(item.path)
        rel_enc = enc.relative_to(ENC_ROOT)
        rel_dec = Path(str(rel_enc)[: -len(EXT)])
        dec = out_for(enc)
        copy_tree_file(enc, pairs_enc, rel_enc)
        copy_tree_file(dec, pairs_dec, rel_dec)
        pair_rows.append(
            {
                "kek": kek,
                "encrypted_rel": str(rel_enc),
                "decrypted_rel": str(rel_dec),
                "encrypted_size": enc.stat().st_size,
                "decrypted_size": dec.stat().st_size,
                "ext": rel_dec.suffix.lower(),
            }
        )

    media_items = select_unrecovered_media(groups)
    path_to_kek = {str(Path(item.path)): kek for kek, files in groups.items() for item in files}
    media_rows = []
    for item in media_items:
        enc = Path(item.path)
        rel = enc.relative_to(ENC_ROOT)
        copy_tree_file(enc, media_bad, rel)
        media_rows.append(
            {
                "kek": path_to_kek.get(str(enc), ""),
                "encrypted_rel": str(rel),
                "size": enc.stat().st_size,
                "ext": Path(str(rel)[: -len(EXT)]).suffix.lower(),
            }
        )

    summary = BUNDLE / "README.txt"
    pair_total = sum(int(r["encrypted_size"]) + int(r["decrypted_size"]) for r in pair_rows)
    media_total = sum(int(r["size"]) for r in media_rows)
    with summary.open("w", encoding="utf-8") as f:
        f.write("Набор для анализа LockBit 3.0\n")
        f.write("=" * 34 + "\n\n")
        f.write("Важно\n")
        f.write("------\n")
        f.write("Все пути в этом наборе относительные. Папку можно переносить и отправлять целиком.\n")
        f.write("Исходные рабочие каталоги на компьютере не указаны специально, чтобы набор не зависел от локального пути пользователя.\n\n")

        f.write("Что это за данные\n")
        f.write("-----------------\n")
        f.write("Файлы были зашифрованы ransomware LockBit 3.0 / LockBit Black, расширение зашифрованных файлов: .xzg9VRelb.\n")
        f.write("В хвосте каждого зашифрованного файла есть FEI/footer с длиной FEI, служебными полями и 128-byte KEK blob.\n")
        f.write("Восстановление выполнялось за счет reuse keystream внутри одной KEK-группы: compressed filename в FEI дает known plaintext, из него строится FEI-keystream, затем из FEI извлекается 64-byte FEK для конкретного файла и тело расшифровывается Salsa20-подобным потоком.\n\n")

        f.write("Использованные инструменты\n")
        f.write("--------------------------\n")
        f.write(_case_value('f9b9642967c87185171d'))
        f.write(_case_value('4e664cfdaa1380e52ea5'))
        f.write(_case_value('ed28b463bbdcf6aa757c'))
        f.write("Локально использовались Python-скрипты и C-утилиты из lockbit-rescue-v2: dump-keystream/brute/direct-decrypt, плюс дополнительные исследовательские скрипты для FEI, metadata, Z3 и media salvage.\n\n")

        f.write("Как расшифровывалось\n")
        f.write("--------------------\n")
        f.write("1. Файлы группировались по KEK fingerprint.\n")
        f.write("2. Для файлов одной группы вычислялся keystream FEI по известному имени файла: original filename -> UTF-16LE -> null termination -> apLib compression.\n")
        f.write("3. Keystream объединялся от нескольких oracle-файлов; конфликты не принимались.\n")
        f.write("4. Дополнительно использовались предсказуемые metadata-поля FEI: compressed filename length, skipped bytes, before/after chunk counts.\n")
        f.write("5. Если весь FEK-диапазон в FEI становился известен, извлекался 64-byte FEK.\n")
        f.write("6. Тело файла расшифровывалось direct-decrypt с параметрами chunking. Обычно для документов/фото это before=3, after=3, skipped=0x520000; для некоторых видео встречались другие профили.\n")
        f.write("7. SUCCESS засчитывался только после проверки формата: PDF/Office ZIP/JPG/MP4/OLE и т.п. Простые magic bytes не считались достаточным доказательством.\n\n")

        f.write("Структура набора\n")
        f.write("----------------\n")
        f.write("01_пары_один_поток/\n")
        f.write("  encrypted/  - зашифрованные версии файлов, относительные пути сохранены.\n")
        f.write("  decrypted/  - соответствующие восстановленные версии, относительные пути совпадают с encrypted без .xzg9VRelb.\n")
        f.write(f"  KEK fingerprint: {kek}\n")
        f.write(f"  Количество пар: {len(pair_rows)}\n")
        f.write(f"  Файлов внутри encrypted + decrypted: {len(pair_rows) * 2}\n")
        f.write(f"  Общий размер пар: {pair_total} bytes ({pair_total / 1024 / 1024:.1f} MB)\n")
        f.write(f"  Расширения decrypted: {dict(Counter(r['ext'] for r in pair_rows))}\n\n")

        f.write("02_невосстановленные_фото_видео/\n")
        f.write("  encrypted/  - зашифрованные media-файлы, которые текущий pipeline не восстановил.\n")
        f.write(f"  Количество файлов: {len(media_rows)}\n")
        f.write(f"  Общий размер: {media_total} bytes ({media_total / 1024 / 1024:.1f} MB)\n")
        f.write(f"  Расширения: {dict(Counter(r['ext'] for r in media_rows))}\n\n")

        f.write("03_видео_позже/\n")
        f.write("  Пустая папка-заготовка. Сюда позже можно добавить отдельный набор по видео после передачи нужного восстановленного ролика.\n\n")

        f.write("Манифесты\n")
        f.write("---------\n")
        f.write("pairs_manifest.csv - соответствие encrypted_rel -> decrypted_rel для пар из одного KEK-потока.\n")
        f.write("unrecovered_media_manifest.csv - список невосстановленных фото/видео с KEK fingerprint, размером и относительным путем.\n\n")

        f.write("Что уже известно по ограничениям\n")
        f.write("--------------------------------\n")
        f.write("FEI metadata и filename-oracle уже хорошо отработали на восстановленных группах.\n")
        f.write("Для больших проблемных фото/видео групп оставшийся неизвестный участок лежит в FEK-области и выглядит случайным.\n")
        f.write("По статистике более чем 10000 известных FEK байты имеют почти максимальную энтропию, поэтому безопасно предсказывать FEK по layout не получилось.\n")
        f.write("Этот набор нужен для независимого анализа reuse/FEI/FEK на компактной выборке без привязки к исходному диску.\n")

    for name, rows in (("pairs_manifest.csv", pair_rows), ("unrecovered_media_manifest.csv", media_rows)):
        with (BUNDLE / name).open("w", encoding="utf-8-sig", newline="") as f:
            fields = list(rows[0].keys()) if rows else ["status"]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    print(f"bundle={BUNDLE}")
    print(f"scanned={scanned} skipped={skipped} groups={len(groups)}")
    print(f"pairs_kek={kek} pair_files={len(pair_rows)} pair_total_mb={pair_total / 1024 / 1024:.1f}")
    print(f"media_files={len(media_rows)} media_total_mb={media_total / 1024 / 1024:.1f}")
    print(f"summary={summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
