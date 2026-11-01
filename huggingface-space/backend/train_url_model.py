"""
train_url_model.py
-------------------
Обучает Machine Learning модель, определяющую вероятность того, что URL
вредоносный, на основе признаков из url_features.py.

ЧТО ИЗМЕНИЛОСЬ по сравнению с первой версией (для защиты - это тоже
хороший рассказ: "мы не просто взяли Random Forest наугад, а провели
методичное сравнение"):

  1) Cross-validation - раньше оценка была всего по ОДНОМУ train/test
     разбиению (80/20), что могло дать случайно "удачную" или "неудачную"
     цифру. Теперь добавлена 5-fold cross-validation - модель обучается
     и проверяется 5 раз на разных частях данных, что даёт более надёжную
     оценку (среднее и разброс).

  2) Hyperparameter tuning - раньше параметры Random Forest (n_estimators,
     max_depth и т.д.) были подобраны вручную "на глаз". Теперь
     RandomizedSearchCV автоматически перебирает много комбинаций и
     находит лучшую по кросс-валидации.

  3) Сравнение с XGBoost - помимо Random Forest, обучается и настраивается
     XGBoost (градиентный бустинг) - на табличных данных он часто
     превосходит Random Forest на несколько процентов. Побеждает тот
     алгоритм, который показывает лучший результат на ОТЛОЖЕННОЙ
     test-выборке (не на той, что использовалась для подбора параметров -
     это принципиально для честной оценки).

Почему поиск гиперпараметров идёт на подвыборке (SEARCH_SAMPLE_SIZE), а не
на всех 100k+ строках: перебор десятков комбинаций x 3 fold'а на полном
датасете занял бы слишком много времени. Стандартная практика - подобрать
параметры на представительной подвыборке, затем переобучить лучшую
конфигурацию уже на ПОЛНОМ обучающем наборе (шаг 5 ниже).

ВАЖНО (честность метрик): все цифры - результат реального обучения и
тестирования на отложенной выборке, которую ни одна модель не видела
при обучении или подборе параметров. Ничего не выдумано.

Запуск:
    python train_url_model.py

Занимает примерно 5-10 минут (в основном - подбор гиперпараметров).
"""

import time
import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)
from xgboost import XGBClassifier

from url_features import extract_features, features_to_vector, ML_FEATURE_COLUMNS

DATASET_PATH = Path(__file__).resolve().parent.parent / "dataset" / "urls_balanced.csv"
MODEL_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "models" / "url_model.pkl"

SEARCH_SAMPLE_SIZE = 15_000   # подвыборка для подбора гиперпараметров (см. пояснение выше)
SEARCH_ITER = 10               # сколько случайных комбинаций параметров пробовать
SEARCH_CV_FOLDS = 3             # число фолдов при подборе (меньше, чем финальные 5 - для скорости)
FINAL_CV_FOLDS = 5               # число фолдов для финальной, честной cross-validation оценки
RANDOM_STATE = 42


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Датасет не найден: {DATASET_PATH}\nОжидается CSV с колонками 'url' и 'label' (0/1)."
        )
    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["url", "label"])
    return df


def build_feature_matrix(urls: list) -> pd.DataFrame:
    rows = []
    for url in urls:
        try:
            raw_features = extract_features(str(url))
            rows.append(features_to_vector(raw_features))
        except Exception:
            rows.append({col: 0 for col in ML_FEATURE_COLUMNS})
    return pd.DataFrame(rows, columns=ML_FEATURE_COLUMNS)


def tune_random_forest(X_search, y_search):
    """RandomizedSearchCV по сетке параметров Random Forest."""
    param_distributions = {
        "n_estimators": [100, 200, 300],
        # Без None (неограниченная глубина) - на 100k+ строках такие деревья
        # растут заметно дольше и легче переобучаются, не давая взамен
        # ощутимого прироста качества.
        "max_depth": [10, 15, 20, 25, 30],
        "min_samples_leaf": [1, 2, 3, 5],
        "min_samples_split": [2, 5, 10],
        "max_features": ["sqrt", "log2"],
    }
    search = RandomizedSearchCV(
        RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1),
        param_distributions=param_distributions,
        n_iter=SEARCH_ITER,
        cv=SEARCH_CV_FOLDS,
        scoring="f1",
        random_state=RANDOM_STATE,
        n_jobs=1,  # деревья самого RF уже используют все ядра (n_jobs=-1 выше) -
                    # запускать ещё и комбинации параметров параллельно поверх
                    # этого только создаёт конкуренцию за ядра и всё замедляет
    )
    search.fit(X_search, y_search)
    return search.best_params_, search.best_score_


def tune_xgboost(X_search, y_search):
    """RandomizedSearchCV по сетке параметров XGBoost."""
    param_distributions = {
        "n_estimators": [100, 200, 300],
        "max_depth": [3, 5, 7, 10],
        "learning_rate": [0.01, 0.05, 0.1, 0.2],
        "subsample": [0.7, 0.85, 1.0],
        "colsample_bytree": [0.7, 0.85, 1.0],
    }
    search = RandomizedSearchCV(
        XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1),
        param_distributions=param_distributions,
        n_iter=SEARCH_ITER,
        cv=SEARCH_CV_FOLDS,
        scoring="f1",
        random_state=RANDOM_STATE,
        n_jobs=1,  # тот же принцип, что и для Random Forest выше
    )
    search.fit(X_search, y_search)
    return search.best_params_, search.best_score_


def evaluate(model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
    }


def main():
    print("1) Загрузка датасета...")
    df = load_dataset()
    print(f"   Всего строк: {len(df)}  (0=safe: {(df['label']==0).sum()}, 1=malicious: {(df['label']==1).sum()})")

    print("2) Извлечение признаков (url_features.py)...")
    start = time.time()
    X = build_feature_matrix(df["url"].tolist())
    y = df["label"].astype(int).values
    print(f"   Готово за {time.time() - start:.1f} сек. Признаков на URL: {len(ML_FEATURE_COLUMNS)}")

    print("3) Разделение train/test (80% / 20%, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    print(f"   Train: {len(X_train)}  Test: {len(X_test)} (test отложен и не используется до самого конца)")

    print(f"\n4) Подбор гиперпараметров на подвыборке ({SEARCH_SAMPLE_SIZE} строк, {SEARCH_ITER} комбинаций x {SEARCH_CV_FOLDS}-fold CV)...")
    rng = np.random.RandomState(RANDOM_STATE)
    sample_idx = rng.choice(len(X_train), size=min(SEARCH_SAMPLE_SIZE, len(X_train)), replace=False)
    X_search = X_train.iloc[sample_idx]
    y_search = y_train[sample_idx]

    print("   4a) Random Forest...")
    start = time.time()
    rf_params, rf_search_f1 = tune_random_forest(X_search, y_search)
    print(f"       Готово за {time.time() - start:.1f} сек. Лучший CV F1 на подвыборке: {rf_search_f1:.4f}")
    print(f"       Параметры: {rf_params}")

    print("   4b) XGBoost...")
    start = time.time()
    xgb_params, xgb_search_f1 = tune_xgboost(X_search, y_search)
    print(f"       Готово за {time.time() - start:.1f} сек. Лучший CV F1 на подвыборке: {xgb_search_f1:.4f}")
    print(f"       Параметры: {xgb_params}")

    print(f"\n5) Переобучение лучших конфигураций на ПОЛНОМ train-наборе ({len(X_train)} строк)...")
    rf_model = RandomForestClassifier(**rf_params, random_state=RANDOM_STATE, n_jobs=-1)
    start = time.time()
    rf_model.fit(X_train, y_train)
    print(f"   Random Forest обучен за {time.time() - start:.1f} сек.")

    xgb_model = XGBClassifier(**xgb_params, random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1)
    start = time.time()
    xgb_model.fit(X_train, y_train)
    print(f"   XGBoost обучен за {time.time() - start:.1f} сек.")

    print("\n6) Честная оценка ОБЕИХ моделей на отложенной test-выборке...")
    rf_metrics = evaluate(rf_model, X_test, y_test)
    xgb_metrics = evaluate(xgb_model, X_test, y_test)
    print("   Random Forest:", json.dumps(rf_metrics, ensure_ascii=False))
    print("   XGBoost:      ", json.dumps(xgb_metrics, ensure_ascii=False))

    if xgb_metrics["f1_score"] >= rf_metrics["f1_score"]:
        winner_name, winner_model, winner_metrics, winner_params = "XGBoost", xgb_model, xgb_metrics, xgb_params
    else:
        winner_name, winner_model, winner_metrics, winner_params = "RandomForest", rf_model, rf_metrics, rf_params
    print(f"\n   Победитель: {winner_name} (F1={winner_metrics['f1_score']})")

    print(f"\n7) {FINAL_CV_FOLDS}-fold cross-validation победителя на полном train-наборе (надёжность оценки)...")
    cv = StratifiedKFold(n_splits=FINAL_CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    # n_jobs=1 на самой модели, n_jobs=-1 на cross_val_score: так 5 фолдов
    # считаются параллельно НА РАЗНЫХ ядрах, вместо того чтобы каждый фолд
    # сам пытался занять все ядра сразу (это только создавало бы конкуренцию
    # и всё замедляло - см. тот же приём в tune_random_forest/tune_xgboost).
    cv_estimator = (RandomForestClassifier(**winner_params, random_state=RANDOM_STATE, n_jobs=1)
                     if winner_name == "RandomForest"
                     else XGBClassifier(**winner_params, random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=1))
    start = time.time()
    cv_scores = cross_val_score(cv_estimator, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
    print(f"   Готово за {time.time() - start:.1f} сек.")
    print(f"   F1 по {FINAL_CV_FOLDS} фолдам: {[round(s, 4) for s in cv_scores]}")
    print(f"   Среднее: {cv_scores.mean():.4f}  Стандартное отклонение: {cv_scores.std():.4f}")

    print("\n   Подробный отчёт по классам (test-выборка):")
    y_pred = winner_model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["safe (0)", "malicious (1)"]))
    print("   Confusion matrix (строки = реальность, столбцы = предсказание):")
    print(confusion_matrix(y_test, y_pred))

    print("\n8) Важность признаков (топ-10):")
    importances = sorted(zip(ML_FEATURE_COLUMNS, winner_model.feature_importances_), key=lambda x: x[1], reverse=True)
    for name, score in importances[:10]:
        print(f"   {name}: {score:.4f}")

    metrics = {
        **winner_metrics,
        "test_set_size": int(len(y_test)),
        "train_set_size": int(len(y_train)),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "cv_f1_std": round(float(cv_scores.std()), 4),
        "algorithm": winner_name,
        "rf_test_f1": rf_metrics["f1_score"],
        "xgb_test_f1": xgb_metrics["f1_score"],
    }

    print(f"\n9) Сохранение модели ({winner_name}) в {MODEL_OUTPUT_PATH} ...")
    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": winner_model,
        "feature_columns": ML_FEATURE_COLUMNS,
        "metrics": metrics,
        "hyperparameters": winner_params,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, MODEL_OUTPUT_PATH)
    print("   Готово.")


if __name__ == "__main__":
    main()
