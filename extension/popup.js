document.addEventListener("DOMContentLoaded", async () => {
  const urlEl = document.getElementById("tab-url");
  const scoreValEl = document.getElementById("score-val");
  const scoreCircleEl = document.getElementById("score-circle");
  const statusBadgeEl = document.getElementById("status-badge");
  const statusDescEl = document.getElementById("status-desc");
  const rescanBtn = document.getElementById("btn-rescan");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    urlEl.textContent = "Faol sahifa topilmadi";
    return;
  }

  urlEl.textContent = tab.url;

  async function scanUrl(url) {
    statusBadgeEl.textContent = "Tahlil qilinmoqda...";
    statusDescEl.textContent = "AI neyron tarmoqlari va evristik tekshiruv ishlamoqda";

    try {
      const resp = await fetch("http://127.0.0.1:8000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
      });

      if (!resp.ok) {
        statusBadgeEl.textContent = "Xatolik";
        statusDescEl.textContent = "Serverdan javob olinmadi";
        return;
      }

      const data = await resp.json();
      renderResult(data);
    } catch (err) {
      statusBadgeEl.textContent = "Backend O'chiq";
      statusDescEl.textContent = "PhishGuard serveri (localhost:8000) ishga tushirilmagan";
      scoreCircleEl.style.borderColor = "#94a3b8";
      scoreValEl.style.color = "#94a3b8";
      scoreValEl.textContent = "OFF";
    }
  }

  function renderResult(data) {
    const score = data.final_score !== undefined ? data.final_score : (data.risk_score || 0);
    scoreValEl.textContent = `${score}%`;

    if (score >= 60) {
      scoreCircleEl.style.borderColor = "#ef4444";
      scoreCircleEl.style.background = "rgba(239, 68, 68, 0.15)";
      scoreValEl.style.color = "#ef4444";
      statusBadgeEl.style.color = "#ef4444";
      statusBadgeEl.textContent = "XAVFLI FISHING!";
      statusDescEl.textContent = data.reasons && data.reasons.length > 0 ? data.reasons[0] : "Saytda xavfli firibgarlik belgilari mavjud";
    } else if (score >= 30) {
      scoreCircleEl.style.borderColor = "#f59e0b";
      scoreCircleEl.style.background = "rgba(245, 158, 11, 0.15)";
      scoreValEl.style.color = "#f59e0b";
      statusBadgeEl.style.color = "#f59e0b";
      statusBadgeEl.textContent = "SHUBHALI SAYT";
      statusDescEl.textContent = "Ehtiyot bo'ling, saytda noaniq xavf belgilari bor";
    } else {
      scoreCircleEl.style.borderColor = "#10b981";
      scoreCircleEl.style.background = "rgba(16, 185, 129, 0.15)";
      scoreValEl.style.color = "#10b981";
      statusBadgeEl.style.color = "#10b981";
      statusBadgeEl.textContent = "XAVFSIZ SAYT";
      statusDescEl.textContent = "Shubhali fishing yoki tahdid belgilari aniqlanmadi";
    }
  }

  rescanBtn.addEventListener("click", () => scanUrl(tab.url));
  scanUrl(tab.url);
});
