"""
error_analysis.py
------------------
Анализирует ОШИБКИ обученной модели (false positives и false negatives)
на отложенной test-выборке - самый ценный шаг для реального улучшения
модели, куда важнее, чем перебор ещё десятка гиперпараметров.

false positive  - модель сказала "вредоносный", а URL на самом деле безопасный
false negative  - модель сказала "безопасный", а URL на самом деле вредоносный
                   (это ОПАСНЕЕ для реального использования - именно такие
                   ошибки пропускают настоящий фишинг)

Что делает скрипт:
  1) загружает models/url_model.pkl и тот же test-набор, что использовался
     при обучении (тот же random_state - то есть модель его не видела);
  2) находит все ошибки и печатает примеры;
  3) сравнивает СРЕДНИЕ значения признаков у ошибок против правильных
     предсказаний - это и есть "поиск паттерна", который может подсказать,
     какой новый признак или порог добавить.

Запуск (после train_url_model.py):
    python error_analysis.py
"""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split

from url_features import extract_features, features_to_vector, ML_FEATURE_COLUMNS

DATASET_PATH = Path(__file__).resolve().parent.parent / "dataset" / "urls_balanced.csv"
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_model.pkl"
RANDOM_STATE = 42
SAMPLES_TO_SHOW = 12


def build_feature_matrix(urls: list) -> pd.DataFrame:
    rows = []
    for url in urls:
        try:
            rows.append(features_to_vector(extract_features(str(url))))
        except Exception:
            rows.append({col: 0 for col in ML_FEATURE_COLUMNS})
    return pd.DataFrame(rows, columns=ML_FEATURE_COLUMNS)


def main():
    if not MODEL_PATH.exists():
        print(f"Модель не найдена: {MODEL_PATH}\nСначала запустите: python train_url_model.py")
        return

    print("1) Загрузка модели и датасета...")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    print(f"   Алгоритм: {bundle.get('metrics', {}).get('algorithm', '?')}")

    df = pd.read_csv(DATASET_PATH).dropna(subset=["url", "label"])
    urls = df["url"].tolist()
    y = df["label"].astype(int).values

    print("2) Извлечение признаков и восстановление ТОГО ЖЕ test-разбиения...")
    X = build_feature_matrix(urls)
    # ВАЖНО: тот же random_state и test_size, что и в train_url_model.py -
    # иначе мы бы случайно проверяли модель на данных, которые она видела при обучении.
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    print("3) Предсказания на test-выборке...")
    y_pred = model.predict(X_test)

    results = pd.DataFrame({
        "url": urls_test,
        "actual": y_test,
        "predicted": y_pred,
    })
    for col in ML_FEATURE_COLUMNS:
        results[col] = X_test[col].values

    false_positives = results[(results.actual == 0) & (results.predicted == 1)]
    false_negatives = results[(results.actual == 1) & (results.predicted == 0)]
    correct = results[results.actual == results.predicted]

    total = len(results)
    print(f"\n   Всего в test-выборке: {total}")
    print(f"   Правильно: {len(correct)} ({len(correct)/total*100:.1f}%)")
    print(f"   False Positives (безопасный -> ошибочно помечен вредоносным): {len(false_positives)} ({len(false_positives)/total*100:.1f}%)")
    print(f"   False Negatives (вредоносный -> ошибочно пропущен как безопасный): {len(false_negatives)} ({len(false_negatives)/total*100:.1f}%)")
    print("\n   ВАЖНО: False Negatives опаснее для реального использования - именно")
    print("   они означают, что настоящий фишинг был пропущен как 'безопасный'.")

    print(f"\n4) Примеры False Positives (первые {SAMPLES_TO_SHOW}):")
    for url in false_positives["url"].head(SAMPLES_TO_SHOW):
        print(f"   {url}")

    print(f"\n5) Примеры False Negatives (первые {SAMPLES_TO_SHOW}):")
    for url in false_negatives["url"].head(SAMPLES_TO_SHOW):
        print(f"   {url}")

    print("\n6) Поиск паттернов: средние значения признаков (ошибки vs правильные)")
    print(f"   {'признак':<26} {'FP среднее':>12} {'FN среднее':>12} {'верно среднее':>15}")
    for col in ML_FEATURE_COLUMNS:
        fp_mean = false_positives[col].mean() if len(false_positives) else float("nan")
        fn_mean = false_negatives[col].mean() if len(false_negatives) else float("nan")
        ok_mean = correct[col].mean()
        # Показываем только признаки, где ошибки заметно отличаются от нормы -
        # это самые вероятные "виновники" и кандидаты на доработку.
        if abs(fp_mean - ok_mean) > 0.25 * (abs(ok_mean) + 1) or abs(fn_mean - ok_mean) > 0.25 * (abs(ok_mean) + 1):
            print(f"   {col:<26} {fp_mean:>12.2f} {fn_mean:>12.2f} {ok_mean:>15.2f}")

    output_path = Path(__file__).resolve().parent.parent / "reports" / "url_model_errors.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([false_positives, false_negatives]).to_csv(output_path, index=False)
    print(f"\n7) Полный список ошибок сохранён в {output_path} (можно открыть в Excel для дальнейшего изучения)")


if __name__ == "__main__":
    main()
