# Dependency Trust Engine — Prototype 1

## Features
- Browser dashboard built with Streamlit.
- Upload or test a `requirements.txt` file.
- Check exact pinned Python package versions against the public OSV.dev vulnerability API.
- Review findings and download a CSV report.

## Run on Windows
Open this folder in VS Code, then open Terminal > New Terminal and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, run this in that terminal and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

A browser should open. If not, open the local URL shown in the terminal, usually `http://localhost:8501`.

## Limits
- Only exact `package==version` entries receive precise version-specific checks.
- No matching record does not prove safety.
- This version does not yet contain machine learning.
- It is a prototype, not a full security audit.

Data source: https://google.github.io/osv.dev/api/
