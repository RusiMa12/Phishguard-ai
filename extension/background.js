/**
 * PhishGuard AI - Background Service Worker (Manifest V3)
 * Real vaqt rejimida har bir ochilgan veb-sahifani fonda avtomatik tekshiradi.
 */

const API_BASE = "http://127.0.0.1:8000/api";
const scanCache = new Map();
const userBypassList = new Set(); // Foydalanuvchi "Tavakkal qilib kirish"ni tanlagan URLlar

// Tab yangilanishini ushlash
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;

  const url = tab.url;

  // Brauzer ichki sahifalari va PhishGuard serverini tekshirish shart emas
  if (
    url.startsWith("chrome://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.includes("127.0.0.1:8000") ||
    url.includes("localhost:8000") ||
    url.includes(chrome.runtime.id)
  ) {
    return;
  }

  // Agar foydalanuvchi ushbu URLga o'z xohishi bilan o'tishga ruxsat bergan bo'lsa
  if (userBypassList.has(url)) {
    chrome.action.setBadgeText({ tabId, text: "IGN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
    return;
  }

  // Keshdan tekshirish
  if (scanCache.has(url)) {
    const cached = scanCache.get(url);
    handleScanResult(tabId, url, cached);
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) return;

    const data = await response.json();
    scanCache.set(url, data);
    handleScanResult(tabId, url, data);
  } catch (err) {
    // Backend o'chiq bo'lsa jim turadi
    console.warn("PhishGuard Backend offline or unreachable:", err);
  }
});

function handleScanResult(tabId, url, data) {
  const score = data.final_score !== undefined ? data.final_score : (data.risk_score || 0);
  const isDangerous = score >= 50 || data.risk_level === "HIGH" || data.risk_level === "CRITICAL" || data.classification === "Potentially Malicious";

  if (isDangerous) {
    // Qizil xavf belgisi
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });

    let brand = data.features?.brand_impersonation || "";
    if (!brand && data.reasons) {
      const brandReason = data.reasons.find(r => /brand/i.test(r));
      if (brandReason) {
        const m = brandReason.match(/brand.*?:\s*([a-zA-Z0-9_\-]+)/i);
        if (m) brand = m[1];
      }
    }

    // Sahifani to'sib, rasmiy SOC ogohlantirish oynasini ochish
    const blockedUrl = chrome.runtime.getURL("blocked.html") +
      `?url=${encodeURIComponent(url)}` +
      `&risk=${score}` +
      `&level=${encodeURIComponent(data.risk_level || "HIGH")}` +
      `&reasons=${encodeURIComponent(JSON.stringify(data.reasons || []))}` +
      `&brand=${encodeURIComponent(brand)}`;

    chrome.tabs.update(tabId, { url: blockedUrl });
  } else {
    // Xavfsiz yashil belgi
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
  }
}

// Popup bilan aloqa
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "allow_bypass" && request.url) {
    userBypassList.add(request.url);
    sendResponse({ success: true });
  } else if (request.action === "get_cached" && request.url) {
    sendResponse({ data: scanCache.get(request.url) || null });
  }
  return true;
});
