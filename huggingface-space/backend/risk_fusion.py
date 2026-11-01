"""
risk_fusion.py
---------------
Финальный уровень анализа EXE: объединяет ДВА независимых источника
в единый Final Risk Score:

  1) local_result  - результат exe_analyzer.combine_static_and_ml()
                      (статические правила + локальная ML-модель, Phase 4-5)
  2) vt_result      - результат services/virustotal.lookup_hash() (Phase 6)

ПОЧЕМУ НЕ ПРОСТОЕ СРЕДНЕЕ (важно для защиты курсовой работы):
Наивный (local_score + vt_score) / 2 одинаково доверяет обеим сторонам
всегда - но это неправильно:
  - если VirusTotal показывает, что 30+ независимых антивирусных
    движков согласны, что файл вредоносный - это очень сильное
    доказательство, которому стоит доверять БОЛЬШЕ, чем нашим
    собственным эвристикам;
  - если всего 1-2 движка что-то заподозрили (у антивирусов бывают
    ложные срабатывания, особенно у менее известных движков) - это
    слабый сигнал, ему нужно доверять МЕНЬШЕ;
  - если VirusTotal вообще недоступен (нет ключа, файл ещё не видели,
    сеть недоступна) - используем ТОЛЬКО локальный анализ и явно
    сообщаем об этом пользователю, а не притворяемся, что VT сказал
    "безопасно".

Поэтому вес VirusTotal в формуле МЕНЯЕТСЯ в зависимости от того,
насколько сильный консенсус движков он показывает (см. _vt_weight).
"""

from risk_engine import score_to_level

# Пороги "силы консенсуса" VirusTotal
STRONG_CONSENSUS_THRESHOLD = 5   # 5+ движков согласны -> сильное доказательство
CLEAN_CONSENSUS_MALICIOUS_MAX = 0
CLEAN_CONSENSUS_SUSPICIOUS_MAX = 0


def _vt_weight(malicious: int, suspicious: int) -> float:
    """
    Возвращает, какую долю Final Score должен занимать VirusTotal
    (оставшееся - вес локального анализа). Формула ступенчатая,
    а не константа - именно это и есть "не простое среднее".
    """
    if malicious == CLEAN_CONSENSUS_MALICIOUS_MAX and suspicious == CLEAN_CONSENSUS_SUSPICIOUS_MAX:
        # Ни один движок ничего не нашёл - сильный (но не абсолютный)
        # сигнал безопасности. Оставляем локальному анализу право
        # "переспорить" в редких случаях (например высокая энтропия +
        # W+X секция - признаки нового, ещё не каталогизированного зловреда).
        return 0.7
    if malicious >= STRONG_CONSENSUS_THRESHOLD:
        # Широкий консенсус независимых движков - самое сильное
        # доказательство, которое у нас вообще есть.
        return 0.8
    # 1-4 движка что-то заподозрили - типичная зона ложных срабатываний,
    # доверяем VT и локальному анализу примерно поровну.
    return 0.5


def fuse_scores(local_score: int, local_reasons: list, local_positive: list, vt_result: dict, subject: str = "file") -> dict:
    """
    Общее ядро объединения (используется и для EXE, и для URL - см.
    combine_final() ниже для EXE-обёртки и api/routes.py для URL).

    Вход:
      local_score     - итоговый счёт от локального анализа (rule + ML)
      local_reasons    - список уже найденных локально причин риска
      local_positive   - список уже найденных локально признаков безопасности
      vt_result        - словарь от virustotal.lookup_hash()/lookup_url()
      subject           - "file" или "URL" - только для текста сообщений

    Выход: final_score, reasons, positive_signals, vt_note
    """
    reasons = list(local_reasons)
    positive_signals = list(local_positive)
    status = vt_result.get("status")

    if status != "completed":
        final_score = local_score
        vt_notes = {
            "not_configured": "VirusTotal verification unavailable. Final score is based on local analysis only.",
            "not_found": f"This {subject} is not yet known to VirusTotal. Final score is based on local analysis only.",
            "pending": "VirusTotal analysis is still in progress. Final score is based on local analysis only for now.",
            "unavailable": "VirusTotal is temporarily unavailable. Final score is based on local analysis only.",
        }
        vt_note = vt_notes.get(status, "VirusTotal result unavailable. Final score is based on local analysis only.")
        return {"final_score": final_score, "reasons": reasons, "positive_signals": positive_signals, "vt_note": vt_note}

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    total = vt_result.get("total_engines", 0) or 1

    raw_ratio_score = (malicious / total) * 100
    if malicious >= STRONG_CONSENSUS_THRESHOLD:
        vt_score = round(max(raw_ratio_score, 75))
    else:
        vt_score = round(raw_ratio_score)

    if malicious == CLEAN_CONSENSUS_MALICIOUS_MAX and suspicious == CLEAN_CONSENSUS_SUSPICIOUS_MAX:
        if local_score >= 60:
            # Zero-Day / Novel Threat Defense:
            # Local heuristics detected strong indicators of malware/phishing, but VirusTotal
            # has not indexed this sample yet. In professional SOC analysis, an uncataloged
            # zero-day sample must NEVER be labeled "Safe" just because external AV databases
            # have not seen it yet. Local indicators take precedence.
            local_weight = 0.8
            vt_weight = 0.2
            final_score = round(local_weight * local_score + vt_weight * vt_score)
            reasons.append(
                f"Potential Zero-Day / Novel threat: Local analysis detected significant threat indicators ({local_score}%), "
                f"while VirusTotal has 0 detections recorded yet (typical for newly engineered or uncataloged threats)."
            )
            vt_note = (
                f"VirusTotal: 0/{total} engines flagged this {subject}. Because local analysis found high threat indicators "
                f"({local_score}%), local heuristics take precedence to protect against zero-day threats."
            )
            return {"final_score": final_score, "reasons": reasons, "positive_signals": positive_signals, "vt_note": vt_note}
        elif local_score >= 40:
            local_weight = 0.6
            vt_weight = 0.4
            final_score = round(local_weight * local_score + vt_weight * vt_score)
        else:
            local_weight = 0.3
            vt_weight = 0.7
            final_score = round(local_weight * local_score + vt_weight * vt_score)
    else:
        vt_weight = _vt_weight(malicious, suspicious)
        local_weight = 1 - vt_weight
        final_score = round(local_weight * local_score + vt_weight * vt_score)

    final_score = min(max(final_score, 0), 100)

    if malicious == 0 and suspicious == 0:
        positive_signals.append(f"No VirusTotal engines flagged this {subject} ({total} engines checked)")
    else:
        reasons.append(
            f"{malicious} out of {total} VirusTotal engines flagged this {subject} as malicious"
            + (f" ({suspicious} more flagged it as suspicious)" if suspicious else "")
        )

    vt_note = (
        f"VirusTotal: {malicious}/{total} engines flagged this {subject} as malicious. "
        f"Weighted at {int(vt_weight*100)}% of the final score "
        f"({'strong multi-engine consensus' if malicious >= STRONG_CONSENSUS_THRESHOLD else 'clean result' if malicious == 0 else 'limited consensus, treated cautiously'})."
    )

    return {"final_score": final_score, "reasons": reasons, "positive_signals": positive_signals, "vt_note": vt_note}


def combine_final(local_result: dict, vt_result: dict) -> dict:
    """
    EXE-обёртка над fuse_scores(): добавляет EXE-специфичную терминологию
    классификации (BENIGN/SUSPICIOUS/MALICIOUS) и рекомендации.

    Вход:
      local_result - словарь от exe_analyzer.combine_static_and_ml()
                      (содержит final_score, indicators, positive_signals)
      vt_result     - словарь от services/virustotal.lookup_hash()

    Выход:
      final_score, risk_level, classification, reasons, recommendations, vt_note
    """
    fused = fuse_scores(
        local_result["final_score"],
        local_result.get("indicators", []),
        local_result.get("positive_signals", []),
        vt_result,
        subject="file",
    )
    final_score = fused["final_score"]

    risk_level, classification_label = score_to_level(final_score)
    classification_map = {
        "Potentially Safe": "BENIGN",
        "Suspicious": "SUSPICIOUS",
        "Potentially Malicious": "MALICIOUS",
    }
    classification = classification_map.get(classification_label, classification_label)

    if risk_level in ("HIGH", "CRITICAL"):
        recommendations = [
            "Do not execute this file.",
            "Verify the source of the executable before proceeding.",
            "Quarantine the file if it is not required.",
        ]
    elif risk_level == "MEDIUM":
        recommendations = ["Exercise caution - verify the file's origin before running it."]
    else:
        recommendations = ["No strong risk indicators were found, but always verify the source of any executable."]

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "classification": classification,
        "reasons": fused["reasons"],
        "positive_signals": fused["positive_signals"],
        "recommendations": recommendations,
        "vt_note": fused["vt_note"],
    }
