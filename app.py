import streamlit as st
import pandas as pd
from aggregator import fetch_and_parse_feeds

st.set_page_config(page_title="SOC Threat Intel Aggregator", layout="wide")

st.title("🛡️ Enterprise Threat Intelligence Aggregator (Non-AI)")
st.subheader("Real-time OSINT Data Normalization & Cross-Feed Correlation Dashboard")

if st.button("🔄 Fetch & Aggregate Live Threat Feeds", type="primary"):
    with st.spinner("Querying active threat channels, removing duplicates, and parsing indicators..."):
        data = fetch_and_parse_feeds()
        df = pd.DataFrame(data)
        
        if not df.empty:
            # Metrics Row
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Unique IOCs Identified", len(df))
            m2.metric("Critical Correlated Overlaps", len(df[df['severity'] == 'CRITICAL']))
            m3.metric("Malicious IP Indicators", len(df[df['type'] == 'IP']))
            m4.metric("Malicious URLs/Domains", len(df[df['type'].isin(['URL', 'DOMAIN'])]))
            
            # Interactive Data Table View
            st.write("### 🗃️ Normalized Threat Intelligence Dataset")
            st.dataframe(df, use_container_width=True)
            
            # Actionable Security Tool Blocklist Export Generator
            st.write("### ⚡ Dynamic Defensive Firewall & EDR Blocklists")
            c1, c2, c3 = st.columns(3)
            
            ips = "\n".join(df[df['type'] == 'IP']['indicator'].tolist())
            c1.download_button("📥 Export Firewall IP Blocklist (.txt)", ips, file_name="firewall_ip_block.txt")
            
            urls = "\n".join(df[df['type'].isin(['URL', 'DOMAIN'])]['indicator'].tolist())
            c2.download_button("📥 Export Web Filter URL Blocklist (.txt)", urls, file_name="web_filter_block.txt")
            
            hashes = "\n".join(df[df['type'].isin(['MD5', 'SHA256'])]['indicator'].tolist())
            c3.download_button("📥 Export EDR Hash Blocklist (.txt)", hashes, file_name="edr_hash_block.txt")
        else:
            st.error("No indicators successfully extracted. Check internet connectivity to feed providers.")
