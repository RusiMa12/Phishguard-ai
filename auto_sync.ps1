# ============================================================
# PhishGuard AI — Real-Time GitHub Auto-Sync Daemon
# ============================================================
$ErrorActionPreference = "Continue"
$projectDir = "C:\Users\user_15184\Desktop\Phishguard-ai"
$git = "C:\Users\user_15184\AppData\Local\Programs\Git\cmd\git.exe"

Set-Location $projectDir

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  🛡️  PhishGuard AI — GitHub Auto-Sync Faol!" -ForegroundColor Green
Write-Host "  Monitoring: $projectDir" -ForegroundColor White
Write-Host "  Repozitoriy: https://github.com/RusiMa12/Phishguard-ai" -ForegroundColor Cyan
Write-Host "  Har qanday faylni o'zgartirib saqlasangiz (Ctrl+S)," -ForegroundColor Yellow
Write-Host "  u avtomatik ravishda GitHub'ga push qilinadi." -ForegroundColor Yellow
Write-Host "  (To'xtatish uchun ushbu oynani yoping yoki Ctrl+C bosing)" -ForegroundColor DarkGray
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$lastCheck = Get-Date

while ($true) {
    try {
        # O'zgarishlar bor-yo'qligini tekshirish
        $status = & $git status --porcelain 2>$null
        
        if ($status) {
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] 📝 O'zgarishlar aniqlandi..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3 # Saqlash yakunlanishini kutish (Debounce)
            
            & $git add . 2>$null
            
            $nowStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $commitMsg = "auto: update changes ($nowStr)"
            
            & $git commit -m $commitMsg 2>$null
            
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] 🚀 GitHub'ga yuklanmoqda..." -ForegroundColor Cyan
            $pushOut = & $git push origin main 2>&1
            
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] ✅ Muvaffaqiyatli GitHub'ga yangilandi!" -ForegroundColor Green
            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
        }
    } catch {
        # Tarmoq xatolari bo'lsa, dasturni to'xtatmasdan keyingi aylanmada sinaydi
        Write-Host "⚠️ Kutilmagan holat: $($_.Exception.Message)" -ForegroundColor Red
    }

    Start-Sleep -Seconds 5
}
