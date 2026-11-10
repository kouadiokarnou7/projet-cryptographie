@echo off
title Messagerie Chiffree E2EE (ElGamal)
echo =========================================================
echo   Lancement de la Messagerie Chiffree E2EE (Multi-Poste)
echo =========================================================
echo.
echo 1. Verification des dependances...
python -m pip install -r requirements.txt >nul 2>&1

echo.
echo 2. Recherche de votre adresse IP locale (Wi-Fi)...
for /f "tokens=4" %%a in ('route print ^| findstr 0.0.0.0 ^| findstr /v "0.0.0.0.*0.0.0.0"') do (
    set LOCAL_IP=%%a
)
echo    Votre IP sur le reseau : %LOCAL_IP%
echo.
echo =========================================================
echo   Pour vous :  http://localhost:5000  ou  http://127.0.0.1:5000
echo   Pour votre ami sur le meme Wi-Fi :  http://%LOCAL_IP%:5000
echo =========================================================
echo.
start http://localhost:5000
python app.py
pause
