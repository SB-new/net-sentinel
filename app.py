import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="Net-Sentinel", page_icon="🛡️")
st.title(" Net-Sentinel Live Dashboard")

def load_data():
    if not os.path.exists("alerts.json"):
        return pd.DataFrame()
    with open("alerts.json", "r") as f:
        data = [json.loads(line) for line in f]
    return pd.DataFrame(data)

# Dashboard Sidebar
st.sidebar.header("System Status")
st.sidebar.success("Engine: Running")
st.sidebar.info("Interface: en1 (Wi-Fi)")

# Main View
df = load_data()

if not df.empty:
    st.subheader("⚠️ Recent Security Alerts")
    st.dataframe(df.sort_values(by="timestamp", ascending=False), use_container_width=True)
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("### Attack Types")
        st.bar_chart(df['type'].value_counts())
    with col2:
        st.write("### Top Offenders")
        st.table(df['source'].value_counts().head(5))
else:
    st.write("No alerts detected yet. Keep the engine running!")

# Auto-refresh helper
if st.button('Refresh Dashboard'):
    st.rerun()