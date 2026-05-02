import streamlit as st
import subprocess
import pandas as pd
import re
from datetime import datetime

st.set_page_config(page_title="Angry VoIP Scanner", layout="wide")

st.title("🚨 Angry VoIP Scanner v1.0")
st.warning("**LAB-ONLY. Authorized targets only. No production scans.**")

# Rules from your list
RULES = {
    'Consistent NAT': {
        'cmd': 'nmap -sV --script nat-* --top-ports 100 {}',
        'good': 'NAT disabled|consistent.*off',
        'bad': 'consistent.*on|NAT enabled',
        'fix': 'Disable Consistent NAT on router (Cisco: `no ip nat service type consistent-type all` global config; pfSense: Firewall > Advanced > Disable NAT Consistency).'
    },
    'SIP ALG': {
        'cmd': 'nmap -sV -p 5060,5061 --script sip-methods,sip-enum-users {}',
        'good': 'ALG disabled|no alg',
        'bad': 'sip-al.*enabled|ALG detected',
        'fix': 'Disable SIP ALG/H.323 (Cisco ASA: `no fixup protocol sip-udp`; pfSense: Firewall > Advanced > SIP ALG off; Netgear: Advanced > WAN Setup > Disable SIP ALG).'
    },
    'H.255/H.323': {
        'cmd': 'nmap -sV -p 1719,1720 {}',
        'good': 'closed|filtered',
        'bad': 'open',
        'fix': 'Block UDP/TCP 1719-1720 (Firewall rules: deny all to H.323 ports).'
    },
    'Starbox Direct': {
        'cmd': 'traceroute -n {} | head -5',
        'good': '1 hop|direct',
        'bad': '2+ hops',
        'fix': 'Connect Starbox directly to modem—no router/switch between.'
    },
    'SIP Ports': {
        'cmd': 'nmap -sU -p 5060,5061 {}',
        'good': 'open',
        'bad': 'closed|filtered',
        'fix': 'Open UDP 5060-61 bi-directional (Firewall: allow from Starbox to Internet).'
    },
    'RTP Ports': {
        'cmd': 'nmap -sU --top-ports 20 -p 10000-20000 {}',
        'good': 'open.*10+',
        'bad': 'closed',
        'fix': 'Open UDP 10000-20000 bi-dir (pfSense: Firewall > Aliases > RTP range).'
    }
}

target = st.text_input("Target IP/range (lab only):", value="192.168.1.0/24")
if st.button("🔍 Full Audit", type="primary"):
    st.subheader(f"Results for {target}")
    results = []
    
    for name, rule in RULES.items():
        with st.spinner(f"Checking {name}..."):
            cmd = rule['cmd'].format(target)
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            
            status = "❌ FAIL" if re.search(rule['bad'], output, re.I) else "✅ PASS"
            device_match = re.search(r'(Cisco|pfSense|Netgear|Starbox|Dell)', output)
            device = device_match.group(1) if device_match else "Generic"
            
            results.append({
                'Check': name,
                'Status': status,
                'Device': device,
                'Fix': rule['fix'],
                'Raw': output[:200] + "..."
            })
    
    df = pd.DataFrame(results)
    st.dataframe(df, use_container_width=True)
    
    # Risk score
    fails = len(df[df['Status'] == '❌ FAIL'])
    st.metric("Risk Score", f"{fails}/6", delta=f"{6-fails - fails}")
    
    csv = df.to_csv(index=False)
    st.download_button("📥 Export CSV", csv, "voip_audit.csv")

st.caption("Raza Norm | Lab demo only | [Portfolio](YOUR_SITE)")
