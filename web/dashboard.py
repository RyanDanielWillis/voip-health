import streamlit as st
import sqlite3
import pandas as pd

st.title("VoIP Network Audit Dashboard")

# Connect to database and load data
conn = sqlite3.connect('audit_data.db')
df = pd.read_sql_query("SELECT * FROM audits", conn)

st.write("Recent Audit Reports:")
st.dataframe(df)

if st.button("Refresh"):
    st.rerun()
