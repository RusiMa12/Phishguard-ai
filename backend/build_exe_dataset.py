"""
build_exe_dataset.py
---------------------
Вспомогательный скрипт: сканирует ДВЕ ЛОКАЛЬНЫЕ папки с .exe файлами
и превращает их в один CSV с числовыми признаками + меткой (0/1),
готовый для train_exe_model.py.

    dataset/exe_samples/benign/      <- сюда кладутся ЛЕГИТИМНЫЕ .exe файлы
    dataset/exe_samples/malicious/   <- сюда кладутся ОБРАЗЦЫ ВРЕДОНОСНОГО ПО

ВАЖНО - ОТКУДА БРАТЬ ФАЙЛЫ (это должен сделать сам студент, не Claude):
  - benign/: подойдут обычные системные утилиты с вашего Windows ПК
    (например копии файлов из C:\\Windows\\System32), портативные
    версии популярных open-source программ и т.д. - то, в чём вы
    уверены, что это НЕ вредоносное ПО.
  - malicious/: НИКОГДА не скачивайте и не запускайте настоящее
    вредоносное ПО на личном компьютере. Если для курсовой работы
    нужен датасет с реальными образцами, это делается ТОЛЬКО через
    контролируемую лабораторию/песочницу вашего учебного заведения
    (изолированная виртуальная машина без доступа к сети), либо через
    уже готовые research-датасеты с ИЗВЛЕЧЁННЫМИ ПРИЗНАКАМИ, а не
    самими файлами (например EMBER, https://github.com/elastic/ember) -
    но учтите, что структура признаков там другая, и её пришлось бы
    адаптировать под exe_features_to_vector() из exe_analyzer.py.
  - Обе папки пустые по умолчанию - это осознанное решение проекта:
    Claude не подбирает и не включает в проект никакие исполняемые
    файлы, тем более вредоносные.

Если папки пустые (или отсутствуют), скрипт вежливо сообщает об этом
и ничего не ломает - train_exe_model.py в этом случае тоже корректно
скажет, что датасета не хватает, и приложение продолжит работать
через static analysis (exe_analyzer.py), как и требуется по ТЗ.

Запуск:
    python build_exe_dataset.py
"""

from pathlib import Path
import csv

from exe_analyzer import parse_pe, calculate_static_risk, exe_features_to_vector, EXE_ML_FEATURE_COLUMNS, InvalidExecutableError

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "dataset" / "exe_samples"
BENIGN_DIR = SAMPLES_DIR / "benign"
MALICIOUS_DIR = SAMPLES_DIR / "malicious"
OUTPUT_CSV = Path(__file__).resolve().parent.parent / "dataset" / "exe_dataset.csv"


def _extract_row(path: Path, label: int):
    try:
        data = path.read_bytes()
        pe_info = parse_pe(data)
    except (InvalidExecutableError, OSError) as exc:
        print(f"  skip {path.name}: {exc}")
        return None
    vector = exe_features_to_vector(len(data), pe_info)
    vector["label"] = label
    return vector


def main():
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    MALICIOUS_DIR.mkdir(parents=True, exist_ok=True)

    benign_files = list(BENIGN_DIR.glob("*.exe"))
    malicious_files = list(MALICIOUS_DIR.glob("*.exe"))

    print(f"Found {len(benign_files)} file(s) in {BENIGN_DIR}")
    print(f"Found {len(malicious_files)} file(s) in {MALICIOUS_DIR}")

    if not benign_files and not malicious_files:
        print(
            "\nBoth folders are empty - this is expected out of the box.\n"
            "See the module docstring at the top of this file for guidance on\n"
            "where such samples may (and may not) come from.\n"
            "train_exe_model.py will report that it needs a dataset and the\n"
            "app will keep working through static analysis only."
        )
        return

    rows = []
    print("\nExtracting features from benign samples...")
    for path in benign_files:
        row = _extract_row(path, label=0)
        if row:
            rows.append(row)

    print("Extracting features from malicious samples...")
    for path in malicious_files:
        row = _extract_row(path, label=1)
        if row:
            rows.append(row)

    if not rows:
        print("No valid PE files could be parsed - nothing to write.")
        return

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXE_ML_FEATURE_COLUMNS + ["label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
