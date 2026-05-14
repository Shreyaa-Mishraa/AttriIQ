@echo off
setlocal ENABLEDELAYEDEXPANSION
cd /d "%~dp0"
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
powershell -NoProfile -Command "(Get-Content config.yaml) -replace 'DEMO_MODE: false','DEMO_MODE: true' | Set-Content config.yaml"
python run_all.py
echo Dashboard at http://127.0.0.1:8050
