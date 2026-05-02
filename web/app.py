import streamlit as st
import sys
import os
import json

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.engine import run_nmap_check

st.title("Angry VoIP Scanner")

# Tab 1: External Scan (VPS -> Remote)
tab1, tab2 = st.tabs(["External Network", "Local Network (Agent Data)"])

with tab1:
    st.subheader("Run External Scan")
    target_ip = st.text_input("Enter Public IP of Starbox")
    if st.button("Audit Public Gateway"):
        res = run_nmap_check(target_ip, "5060,10000-20000,8021,22,2222,123,443")
        st.json(res)

with tab2:
    st.subheader("Ingest Local Agent Data")
    st.write("Run `local_scanner.py` on your local network, then paste the JSON output here:")
    local_data = st.text_area("Paste local JSON results")
    if st.button("Submit Data"):
        if local_data:
            st.session_state.local_results = json.loads(local_data)
            st.success("Data ingested!")
        
    if 'local_results' in st.session_state:
        st.json(st.session_state.local_results)
