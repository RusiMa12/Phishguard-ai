"""
brand_radar.py
--------------
O'zbekiston brendlari va kompaniyalarining nomlarini himoya qilish uchun
Typosquatting, Omoglif (Homoglyph/Punycode), va soxta klon domenlarni
aniqlash va tahlil qilish xizmati.
"""

from typing import List, Dict, Any
import re
from urllib.parse import urlparse
from url_features import extract_features
from ml_url_model import predict_probability

# O'zbekistonning eng ommabop 10 ta brendi
UZBEK_BRAND_PRESETS = [
    {
        "id": "payme",
        "name": "Payme (Inspire Group)",
        "official_domain": "payme.uz",
        "category": "To'lov tizimi",
        "icon": "💳",
        "keywords": ["payme", "pay", "me"]
    },
    {
        "id": "click",
        "name": "Click Evolution",
        "official_domain": "click.uz",
        "category": "To'lov tizimi",
        "icon": "📲",
        "keywords": ["click", "clik"]
    },
    {
        "id": "uzum",
        "name": "Uzum Market & Bank",
        "official_domain": "uzum.uz",
        "category": "Ekosistema & Bank",
        "icon": "🍇",
        "keywords": ["uzum", "uzumbank", "nasiya"]
    },
    {
        "id": "hamkorbank",
        "name": "Hamkorbank ATB",
        "official_domain": "hamkorbank.uz",
        "category": "Tijorat banki",
        "icon": "🏦",
        "keywords": ["hamkorbank", "hamkor"]
    },
    {
        "id": "nbu",
        "name": "O'zbekiston Milliy Banki (NBU)",
        "official_domain": "nbu.uz",
        "category": "Davlat banki",
        "icon": "🏛️",
        "keywords": ["nbu", "milliybank"]
    },
    {
        "id": "anorbank",
        "name": "Anorbank",
        "official_domain": "anorbank.uz",
        "category": "Raqamli bank",
        "icon": "🍎",
        "keywords": ["anorbank", "anor"]
    },
    {
        "id": "soliq",
        "name": "Davlat Soliq Qo'mitasi",
        "official_domain": "soliq.uz",
        "category": "Davlat xizmati",
        "icon": "📑",
        "keywords": ["soliq", "my3soliq"]
    },
    {
        "id": "mygov",
        "name": "Yagona Portal (MyGov)",
        "official_domain": "my.gov.uz",
        "category": "Davlat portali",
        "icon": "🇺🇿",
        "keywords": ["mygov", "gov"]
    },
    {
        "id": "kunuz",
        "name": "Kun.uz Axborot Portali",
        "official_domain": "kun.uz",
        "category": "OAV / Media",
        "icon": "📰",
        "keywords": ["kun", "kunuz"]
    },
    {
        "id": "ipakyuli",
        "name": "Ipak Yo'li Banki",
        "official_domain": "ipakyulibank.uz",
        "category": "Tijorat banki",
        "icon": "💎",
        "keywords": ["ipakyuli", "ipakyulibank"]
    }
]

# Fishingchilar tez-tez ishlatadigan shubhali prefiks va suffikslar
SUSPICIOUS_AFFIXES = [
    "login", "verify", "online", "bonus", "tolov", "kredit",
    "cabinet", "security", "support", "auth", "secure", "pay", "portal", "yutuq"
]

# Kiber-jinoyatchilar ishlatadigan arzon / xavfli TLDlar
SUSPICIOUS_TLDS = [
    ".click", ".top", ".site", ".cc", ".tk", ".ml", ".cfd", ".live", ".link", ".xyz", ".buzz"
]

# Omoglif almashtirishlar (Lotin harflari o'rniga vizual o'xshash Kirill harflari)
HOMOGLYPH_MAP = {
    'a': 'а',  # Cyrillic small a
    'e': 'е',  # Cyrillic small ie
    'o': 'о',  # Cyrillic small o
    'p': 'р',  # Cyrillic small er
    'c': 'с',  # Cyrillic small es
    'i': 'і',  # Cyrillic/Ukrainian small i
    'x': 'х',  # Cyrillic small ha
    'y': 'у',  # Cyrillic small u
}


def generate_brand_mutations(brand_name: str, base_domain: str) -> List[Dict[str, Any]]:
    """
    Berilgan brend nomi va domeni uchun ehtimoliy fishing klonlarini generatsiya qiladi.
    Mutatsiya turlari:
    1. Homoglyph / Punycode
    2. Typosquatting (harf tushishi, qo'shilishi, o'rin almashishi)
    3. Phishing Affixes (payme-bonus, click-tolov)
    4. TLD Hijacking (payme.click, uzum.top)
    """
    mutations = []
    brand_clean = re.sub(r'[^a-zA-Z0-9]', '', brand_name.lower())
    
    # Extract base name without TLD (e.g., 'payme' from 'payme.uz')
    domain_parts = base_domain.split('.')
    core_name = domain_parts[0] if domain_parts else brand_clean

    # 1. HOMOGLYPH MUTATIONS
    for char, cyr in HOMOGLYPH_MAP.items():
        if char in core_name:
            homo_name = core_name.replace(char, cyr, 1)
            # Punycode encoding
            try:
                puny = homo_name.encode('idna').decode('ascii')
                mutations.append({
                    "clone_domain": f"{homo_name}.uz",
                    "punycode": f"{puny}.uz",
                    "mutation_type": "Omoglif (Punycode IDN)",
                    "severity": "CRITICAL",
                    "heuristic_score": 96,
                    "description": f"Lotin '{char}' harfi vizual o'xshash Kirill '{cyr}' ({puny}) bilan almashtirilgan"
                })
            except Exception:
                pass

    # 2. PHISHING AFFIXES (Eng ko'p uchraydigan O'zbekiston fishing uslubi)
    for affix in SUSPICIOUS_AFFIXES[:7]:
        mutations.append({
            "clone_domain": f"{core_name}-{affix}.uz",
            "punycode": "",
            "mutation_type": "Soxta Suffiks (Klon)",
            "severity": "HIGH",
            "heuristic_score": 88,
            "description": f"Brend nomiga '{affix}' qo'shimchasi ulab soxta xizmat ko'rinishi berilgan"
        })
        mutations.append({
            "clone_domain": f"{core_name}-{affix}{SUSPICIOUS_TLDS[0]}",
            "punycode": "",
            "mutation_type": "Xavfli TLD + Suffiks",
            "severity": "CRITICAL",
            "heuristic_score": 94,
            "description": f"Xavfli zona ({SUSPICIOUS_TLDS[0]}) va '{affix}' soxta xizmat qo'shimchasi"
        })

    # 3. TYPOSQUATTING (Harflar xatosi)
    # Double letter
    if len(core_name) >= 3:
        mutations.append({
            "clone_domain": f"{core_name}{core_name[-1]}.uz",
            "punycode": "",
            "mutation_type": "Typosquatting (Takror harf)",
            "severity": "HIGH",
            "heuristic_score": 82,
            "description": f"Foydalanuvchi yozishda adashishi uchun oxirgi harf takrorlangan"
        })
    # Omitted letter
    if len(core_name) > 4:
        omitted = core_name[:-1]
        mutations.append({
            "clone_domain": f"{omitted}.uz",
            "punycode": "",
            "mutation_type": "Typosquatting (Tushib qolgan harf)",
            "severity": "MEDIUM",
            "heuristic_score": 75,
            "description": f"Brend nomidan bitta harf ataylab olib tashlangan"
        })

    # 4. TLD HIJACKING
    for tld in SUSPICIOUS_TLDS[:5]:
        mutations.append({
            "clone_domain": f"{core_name}{tld}",
            "punycode": "",
            "mutation_type": "TLD Hijacking (Begona zona)",
            "severity": "HIGH",
            "heuristic_score": 90,
            "description": f"Rasmiy .uz o'rniga kiber-jinoyatchilar xavfli {tld} zonasidan foydalangan"
        })

    return mutations


def scan_brand_impersonation(brand_id: str, custom_name: str = "", custom_domain: str = "") -> Dict[str, Any]:
    """
    Tanlangan brend yoki kiritilgan ixtiyoriy domen bo'yicha
    klon domenlarni aniqlash va xavflilik darajasini baholash.
    """
    target_preset = None
    if brand_id and brand_id != "custom":
        for p in UZBEK_BRAND_PRESETS:
            if p["id"] == brand_id:
                target_preset = p
                break

    if target_preset:
        brand_name = target_preset["name"]
        official_domain = target_preset["official_domain"]
        category = target_preset["category"]
    else:
        brand_name = custom_name.strip() or "Custom Target"
        official_domain = custom_domain.strip() or f"{brand_name.lower()}.uz"
        category = "Foydalanuvchi maqsadi"

    raw_mutations = generate_brand_mutations(brand_name, official_domain)

    # ML va Leksik Tahlil integratsiyasi
    scored_results = []
    high_risk_count = 0
    critical_count = 0

    for m in raw_mutations:
        clone_url = f"https://{m['clone_domain']}/"
        try:
            features = extract_features(clone_url)
            ml_prob = predict_probability(features)
            if ml_prob is not None:
                ml_score = round(ml_prob * 100, 1)
            else:
                ml_score = m["heuristic_score"]
        except Exception:
            ml_score = m["heuristic_score"]

        # Final consensus score for this clone
        final_risk = round(0.5 * m["heuristic_score"] + 0.5 * ml_score)
        
        # Categorize
        if final_risk >= 85:
            level = "CRITICAL"
            critical_count += 1
        elif final_risk >= 65:
            level = "HIGH"
            high_risk_count += 1
        else:
            level = "MEDIUM"

        scored_results.append({
            "clone_domain": m["clone_domain"],
            "punycode": m.get("punycode", ""),
            "mutation_type": m["mutation_type"],
            "risk_score": final_risk,
            "risk_level": level,
            "description": m["description"],
            "is_live_threat": final_risk >= 80,
            "recommended_action": "Bloklash / CERT ogohlantirish" if final_risk >= 85 else "Monitoring qilish"
        })

    # Sort descending by risk score
    scored_results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "status": "success",
        "brand_name": brand_name,
        "official_domain": official_domain,
        "category": category,
        "total_analyzed": len(scored_results),
        "critical_count": critical_count,
        "high_risk_count": high_risk_count,
        "safe_official": official_domain,
        "results": scored_results
    }
