"""
train_exe_model.py
-------------------
Обучает Random Forest классификатор для EXE-файлов: BENIGN / SUSPICIOUS / MALICIOUS.

ЧЕСТНОЕ ОГРАНИЧЕНИЕ ЭТОГО ПРОЕКТА (важно сказать на защите открыто):
В отличие от URL-модели (Phase 3), для которой существует много открытых
датасетов из простых текстовых строк, датасеты вредоносного ПО - это
исполняемые файлы, распространение которых требует специальной
инфраструктуры (изолированные лаборатории, юридические соглашения).
Claude не скачивает и не хранит вредоносное ПО ни при каких условиях.

Поэтому этот скрипт спроектирован так:
  - если dataset/exe_dataset.csv не существует или в нём слишком мало
    строк - скрипт ЧЕСТНО об этом сообщает и завершается, НЕ создавая
    фиктивную "обученную" модель;
  - если файл существует и данных достаточно - скрипт обучает модель
    и показывает РЕАЛЬНЫЕ метрики, точно так же, как train_url_model.py;
  - в любом случае само приложение продолжает работать через
    exe_analyzer.calculate_static_risk() (rule-based анализ), как
    прямо разрешено требованиями проекта.

Как получить dataset/exe_dataset.csv - см. build_exe_dataset.py.

Запуск:
    python train_exe_model.py
"""

import time
import json
from pathlib import Path

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from exe_analyzer import EXE_ML_FEATURE_COLUMNS

DATASET_PATH = Path(__file__).resolve().parent.parent / "dataset" / "exe_dataset.csv"
MODEL_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "models" / "exe_model.pkl"
MIN_ROWS_REQUIRED = 20  # символический минимум - обучать на 2-3 примерах бессмысленно


def main():
    print("1) Looking for dataset/exe_dataset.csv ...")

    if not DATASET_PATH.exists():
        print(
            f"\n   Dataset not found at {DATASET_PATH}\n\n"
            "   This is EXPECTED out of the box - PhishGuard AI does not ship with\n"
            "   any executable samples, malicious or otherwise.\n\n"
            "   To train the EXE ML model:\n"
            "     1. Read the docstring in build_exe_dataset.py for guidance on\n"
            "        where benign/malicious samples may (and may not) come from.\n"
            "     2. Place .exe files in dataset/exe_samples/benign/ and\n"
            "        dataset/exe_samples/malicious/\n"
            "     3. Run: python build_exe_dataset.py\n"
            "     4. Run this script again.\n\n"
            "   Until then, PhishGuard AI continues to work normally through\n"
            "   static PE analysis alone (exe_analyzer.py) - no ML required.\n"
        )
        return

    df = pd.read_csv(DATASET_PATH)
    print(f"   Found {len(df)} rows.")

    if len(df) < MIN_ROWS_REQUIRED or df["label"].nunique() < 2:
        print(
            f"\n   Not enough data to train a meaningful model "
            f"(need >= {MIN_ROWS_REQUIRED} rows with both classes present).\n"
            "   Add more samples via build_exe_dataset.py and try again.\n"
            "   The app continues to work through static analysis only.\n"
        )
        return

    X = df[EXE_ML_FEATURE_COLUMNS]
    y = df["label"].astype(int)

    print("2) Splitting train/test (80% / 20%, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Train: {len(X_train)}  Test: {len(X_test)}")

    print("3) Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200, max_depth=15, min_samples_leaf=2,
        random_state=42, n_jobs=-1,
    )
    start = time.time()
    model.fit(X_train, y_train)
    print(f"   Trained in {time.time() - start:.1f}s")

    print("4) Evaluating on the held-out test set...")
    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "test_set_size": int(len(y_test)),
        "train_set_size": int(len(y_train)),
    }
    print(json.dumps(metrics, indent=2))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["benign (0)", "malicious (1)"], zero_division=0))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n5) Feature importance:")
    importances = sorted(zip(EXE_ML_FEATURE_COLUMNS, model.feature_importances_), key=lambda x: x[1], reverse=True)
    for name, score in importances:
        print(f"   {name}: {score:.4f}")

    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "feature_columns": EXE_ML_FEATURE_COLUMNS,
        "metrics": metrics,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, MODEL_OUTPUT_PATH)
    print(f"\n6) Saved model to {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
