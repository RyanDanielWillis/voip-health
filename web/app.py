import streamlit as st
import sys
import os
import json
import pandas as pd
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner.engine import run_cmd

st.set_page_config(page_title="Angry VoIP Scanner", layout="wide")
st.title("🛡️ Angry VoIP Scanner")
target = st.sidebar.text_input("Target IP/CIDR:", "192.168.1.0/24")

with open('configs/rules.json', 'r') as f:
    RULES = json.load(f)

if st.sidebar.button("Run Audit"):
    results = []
    for cat, checks in RULES.items():
        st.subheader(cat)
        for name, rule in checks.items():
            out = run_cmd(rule['cmd'] + " " + target, target)
            status = "❌ FAIL" if re.search(rule['bad'], out, re.I) else "✅ PASS"
            results.append({'Check': name, 'Status': status, 'Fix': rule['fix']})
    st.table(pd.DataFrame(results))
st.sidebar.markdown("---")
st.sidebar.info("v1.0.0 - Modular Scanner")
