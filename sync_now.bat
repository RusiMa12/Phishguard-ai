@echo off
title PhishGuard AI - GitHub Quick Sync
cd /d "C:\Users\user_15184\Desktop\Phishguard-ai"
echo ========================================================
echo   PhishGuard AI — GitHub Bilan Tezkor Sinxronizatsiya
echo ========================================================
echo.
"C:\Users\user_15184\AppData\Local\Programs\Git\cmd\git.exe" add .
"C:\Users\user_15184\AppData\Local\Programs\Git\cmd\git.exe" commit -m "update: quick sync %date% %time%"
echo.
echo GitHub'ga yuklanmoqda...
"C:\Users\user_15184\AppData\Local\Programs\Git\cmd\git.exe" push origin main
echo.
echo ========================================================
echo   Muvaffaqiyatli yuklandi! Oyna 3 soniyada yopiladi.
echo ========================================================
timeout /t 3 >nul
