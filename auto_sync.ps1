# ============================================================
# PhishGuard AI - Real-Time GitHub Auto-Sync Daemon
# ============================================================
$ErrorActionPreference = "Continue"
$projectDir = "C:\Users\user_15184\Desktop\Phishguard-ai"
$git = "C:\Users\user_15184\AppData\Local\Programs\Git\cmd\git.exe"

Set-Location $projectDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PhishGuard AI -- GitHub Auto-Sync Faol!" -ForegroundColor Green
Write-Host "  Monitoring: $projectDir" -ForegroundColor White
Write-Host "  Repozitoriy: https://github.com/RusiMa12/Phishguard-ai" -ForegroundColor Cyan
Write-Host "  Har qanday faylni o'zgartirib saqlasangiz (Ctrl+S)," -ForegroundColor Yellow
Write-Host "  u avtomatik ravishda GitHub'ga push qilinadi." -ForegroundColor Yellow
Write-Host "  (To'xtatish uchun ushbu oynani yoping yoki Ctrl+C bosing)" -ForegroundColor DarkGray
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    try {
        $status = & $git status --porcelain 2>$null
        
        if ($status) {
            $timeStr = (Get-Date).ToString("HH:mm:ss")
            Write-Host "[$timeStr] [O'zgarish] Yangi o'zgarishlar aniqlandi..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            
            & $git add . 2>$null
            
            $nowStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $commitMsg = "auto: sync changes ($nowStr)"
            
            & $git commit -m $commitMsg 2>$null
            
            Write-Host "[$timeStr] [Yuklanmoqda] GitHub'ga push qilinmoqda..." -ForegroundColor Cyan
            $pushOut = & $git push origin main 2>&1
            
            $timeDone = (Get-Date).ToString("HH:mm:ss")
            Write-Host "[$timeDone] [Muvaffaqiyatli] GitHub'ga yangilandi!" -ForegroundColor Green
            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[Xatolik] $($_.Exception.Message)" -ForegroundColor Red
    }

    Start-Sleep -Seconds 5
}
