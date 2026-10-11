import re
import requests
import pandas as pd
import streamlit as st

OSV_URL = "https://api.osv.dev/v1/querybatch"

def parse_requirements(text):
    packages = []
    skipped = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(" #", 1)[0].split(";", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(==|===|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.+!-]+)?", line)
        if not match:
            skipped.append(raw)
            continue
        name, operator, version = match.groups()
        pinned = operator in ("==", "===") and bool(version)
        packages.append({"name": name, "version": version if pinned else "Not pinned", "pinned": pinned})
    unique, seen = [], set()
    for p in packages:
        key = (p["name"].lower(), p["version"])
        if key not in seen:
            unique.append(p)
            seen.add(key)
    return unique, skipped

def check_osv(packages):
    pinned = [p for p in packages if p["pinned"]]
    if not pinned:
        return {}, "No exact versions found. Use lines like requests==2.31.0."
    payload = {"queries": [
        {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]}
        for p in pinned
    ]}
    try:
        response = requests.post(OSV_URL, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return {}, f"Could not contact OSV.dev. Check your internet connection. Details: {exc}"
    except ValueError:
        return {}, "OSV.dev returned an unreadable response."
    results = {}
    for p, result in zip(pinned, data.get("results", [])):
        results[(p["name"].lower(), p["version"])] = result.get("vulns", [])
    return results, None

def make_report(packages, results):
    rows = []
    for p in packages:
        key = (p["name"].lower(), p["version"])
        if not p["pinned"]:
            rows.append({"Package": p["name"], "Version": p["version"], "Finding": "Version not pinned", "Records": "Not checked", "Details": "Use an exact version for a precise lookup."})
            continue
        vulns = results.get(key, [])
        if vulns:
            details = "; ".join(f'{v.get("id", "OSV record")}: {v.get("summary", "No summary")}' for v in vulns[:3])
            finding = "Known vulnerability record(s) found"
        else:
            details = "No matching record returned. This does not prove the package is safe."
            finding = "No matching OSV record returned"
        rows.append({"Package": p["name"], "Version": p["version"], "Finding": finding, "Records": len(vulns), "Details": details})
    return pd.DataFrame(rows)

st.set_page_config(page_title="Dependency Trust Engine", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:linear-gradient(180deg,#f5f8fc 0%,#eaf1f7 100%)}
.block-container {max-width:1200px;padding-top:2rem}
.hero {padding:1.6rem;border-radius:18px;color:white;background:linear-gradient(120deg,#10243a,#176b75);margin-bottom:1rem}
.hero h1 {margin:0}.hero p {color:#e0f2f1;margin-bottom:0}
</style>
<div class="hero"><h1>🛡️ Dependency Trust Engine</h1>
<p>Check Python project dependencies against real public vulnerability records.</p></div>
""", unsafe_allow_html=True)
st.info("Prototype 1: checks exact package versions against OSV.dev. It does not yet use machine learning and is not a complete security audit.")

with st.sidebar:
    st.header("How it works")
    st.write("1. Upload a requirements file.")
    st.write("2. Click Analyze.")
    st.write("3. Review the findings and export a CSV report.")
    st.divider()
    st.caption("Data source: OSV.dev public vulnerability database.")
    st.caption("This code does not save your uploaded file to disk.")

sample = "requests==2.31.0\nflask==2.0.0\ndjango==3.2.0\nnumpy==1.26.4\npandas==2.2.0\n"
uploaded = st.file_uploader("Upload requirements.txt", type=["txt"])
use_sample = st.checkbox("Use sample dependencies to test the app", value=uploaded is None)
text = None
if uploaded is not None:
    try:
        text = uploaded.getvalue().decode("utf-8-sig")
    except UnicodeDecodeError:
        st.error("Please upload a UTF-8 text file.")
elif use_sample:
    text = sample
    with st.expander("Preview sample file"):
        st.code(sample, language="text")

if text is not None and st.button("Analyze dependencies", type="primary", use_container_width=True):
    packages, skipped = parse_requirements(text)
    if not packages:
        st.error("No package entries found. Check the file contents.")
    else:
        with st.spinner("Checking pinned versions against OSV.dev..."):
            results, error = check_osv(packages)
        if error:
            st.warning(error)
        if skipped:
            st.warning(f"{len(skipped)} line(s) could not be parsed and were skipped.")
        report = make_report(packages, results)
        checked = sum(p["pinned"] for p in packages)
        found = sum(len(results.get((p["name"].lower(), p["version"]), [])) for p in packages if p["pinned"])
        c1, c2, c3 = st.columns(3)
        c1.metric("Packages found", len(packages))
        c2.metric("Exact versions checked", checked)
        c3.metric("Vulnerability records returned", found)
        st.subheader("Analysis results")
        st.dataframe(report, use_container_width=True, hide_index=True)
        st.download_button("Download CSV report", report.to_csv(index=False).encode("utf-8"), "dependency_trust_report.csv", "text/csv")
        st.subheader("How to read this")
        st.write("- **Known vulnerability record(s) found:** investigate the listed records and affected-version information.\n- **No matching OSV record returned:** this is not proof of safety.\n- **Version not pinned:** the app cannot perform a precise version lookup for that line.")
        st.caption("This prototype does not inspect source code, prove a package is malicious, or replace a security review.")
