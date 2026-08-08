import json
import sqlite3
import pandas as pd
import streamlit as st
import requests

# Database file path (ensure this path is correct for your environment)
DB_FILE = "logs\\honeypot.db"

# --- 1. DATABASE QUERY HELPER ---
def run_query(query, params=()):
    """Executes a SQL query against the SQLite database and returns a Pandas DataFrame."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            return pd.read_sql(query, conn, params=params)
    except sqlite3.OperationalError:
        return pd.DataFrame()

# --- 2. STREAMLIT CONFIG & SIDEBAR FILTERS ---
st.set_page_config(page_title="Honeypot Dashboard", layout="wide")
st.title("Cowrie Honeypot Analysis")

st.sidebar.header("Global Filters")

# Fetch available nodes dynamically from SQLite
available_nodes_df = run_query("SELECT DISTINCT node FROM events WHERE node IS NOT NULL")

if not available_nodes_df.empty:
    nodes = sorted(available_nodes_df['node'].dropna().tolist())
    selected_nodes = st.sidebar.multiselect("Filter by Node", options=nodes, default=nodes)
else:
    nodes = []
    selected_nodes = []

# Construct a parameterized SQL WHERE clause for node filtering
if selected_nodes:
    placeholders = ",".join("?" * len(selected_nodes))
    node_where = f"AND node IN ({placeholders})"
    node_params = tuple(selected_nodes)
else:
    # If no nodes selected, match nothing
    node_where = "AND 1=0"
    node_params = ()

st.sidebar.divider()
if st.sidebar.button("Refresh Data"):
    st.rerun()

# --- 3. TAB NAVIGATION ---
tab_overview, tab_credentials, tab_files, tab_network, tab_explorer, tab_timeline = st.tabs([
    "Overview & Traffic", 
    "Key Credentials", 
    "Malware & Commands",
    "Proxy & Tunneling",
    "Catch-All Event Explorer",
    "Attacker Timeline"
])

# ==========================================
# TAB 1: OVERVIEW & TRAFFIC
# ==========================================
with tab_overview:
    # High-level aggregate metrics directly from SQL
    total_events_df = run_query(f"SELECT COUNT(*) as count FROM events WHERE 1=1 {node_where}", node_params)
    unique_ips_df = run_query(f"SELECT COUNT(DISTINCT src_ip) as count FROM events WHERE src_ip IS NOT NULL {node_where}", node_params)
    
    total_events = total_events_df.iloc[0]['count'] if not total_events_df.empty else 0
    unique_ips = unique_ips_df.iloc[0]['count'] if not unique_ips_df.empty else 0
    
    c1, c2 = st.columns(2)
    c1.metric("Total Captured Events", f"{total_events:,}")
    c2.metric("Unique Attacker IPs", f"{unique_ips:,}")
    
    st.divider()
    
    chart_col1, chart_col2, chart_col3 = st.columns(3)
    
    with chart_col1:
        st.subheader("Top Attacker IPs")
        top_ips = run_query(f"""
            SELECT src_ip, COUNT(*) as Count 
            FROM events 
            WHERE src_ip IS NOT NULL {node_where} 
            GROUP BY src_ip 
            ORDER BY Count DESC 
            LIMIT 10
        """, node_params)
        if not top_ips.empty:
            st.bar_chart(top_ips.set_index('src_ip'))
            
    with chart_col2:
        st.subheader("Event Types")
        top_events = run_query(f"""
            SELECT eventid, COUNT(*) as Count 
            FROM events 
            WHERE eventid IS NOT NULL {node_where} 
            GROUP BY eventid 
            ORDER BY Count DESC 
            LIMIT 10
        """, node_params)
        if not top_events.empty:
            st.bar_chart(top_events.set_index('eventid'))
            
    with chart_col3:
        st.subheader("Attacks per Node")
        node_counts = run_query(f"""
            SELECT node, COUNT(*) as Count 
            FROM events 
            WHERE node IS NOT NULL {node_where} 
            GROUP BY node 
            ORDER BY Count DESC
        """, node_params)
        if not node_counts.empty:
            st.bar_chart(node_counts.set_index('node'))

# ==========================================
# TAB 2: CREDENTIALS
# ==========================================
with tab_credentials:
    st.header("Credential Analytics")
    
    # Query all authentication attempts
    logins = run_query(f"""
        SELECT timestamp, node, src_ip, username, password, eventid 
        FROM events 
        WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed') {node_where}
    """, node_params)
    
    if not logins.empty:
        logins['status'] = logins['eventid'].map({
            'cowrie.login.success': 'Success',
            'cowrie.login.failed': 'Failed'
        })
        
        st.subheader("Most Common Attack Patterns")
        col_u, col_p, col_combo = st.columns(3)
        
        with col_u:
            st.markdown("**Top 10 Targeted Usernames**")
            top_users = logins['username'].value_counts().head(10).reset_index()
            top_users.columns = ['Username', 'Attempts']
            st.dataframe(top_users, use_container_width=True, hide_index=True)
            
        with col_p:
            st.markdown("**Top 10 Attempted Passwords**")
            top_pass = logins['password'].value_counts().head(10).reset_index()
            top_pass.columns = ['Password', 'Attempts']
            st.dataframe(top_pass, use_container_width=True, hide_index=True)
            
        with col_combo:
            st.markdown("**Top 10 User:Password Combinations**")
            combos = logins.groupby(['username', 'password']).size().reset_index(name='Attempts')
            top_combos = combos.sort_values(by='Attempts', ascending=False).head(10)
            st.dataframe(top_combos, use_container_width=True, hide_index=True)
            
        st.divider()
        
        st.subheader("Advanced Credential Search")
        search_mode = st.radio("Search Mode", ["Global Keyword Search (Every Field)", "Field-by-Field Search"], horizontal=True)
        
        filtered_logins = logins.copy()
        
        if search_mode == "Global Keyword Search (Every Field)":
            global_query = st.text_input("Type any keyword to search across all credential fields (IP, User, Pass, Status):", "")
            if global_query:
                q = global_query.lower()
                mask = filtered_logins.astype(str).apply(lambda x: x.str.lower().str.contains(q).any(), axis=1)
                filtered_logins = filtered_logins[mask]
        else:
            fc1, fc2, fc3, fc4 = st.columns(4)
            with fc1:
                ip_search = st.text_input("Filter by IP:", "")
            with fc2:
                user_search = st.text_input("Filter by Username:", "")
            with fc3:
                pass_search = st.text_input("Filter by Password:", "")
            with fc4:
                status_select = st.multiselect("Filter Status:", ['Success', 'Failed'], default=['Success', 'Failed'])
            
            filtered_logins = filtered_logins[filtered_logins['status'].isin(status_select)]
            if ip_search:
                filtered_logins = filtered_logins[filtered_logins['src_ip'].astype(str).str.lower().str.contains(ip_search.lower())]
            if user_search:
                filtered_logins = filtered_logins[filtered_logins['username'].astype(str).str.lower().str.contains(user_search.lower())]
            if pass_search:
                filtered_logins = filtered_logins[filtered_logins['password'].astype(str).str.lower().str.contains(pass_search.lower())]

        st.write(f"Showing **{len(filtered_logins):,}** matching credential logs:")
        
        display_login_cols = ['timestamp', 'node', 'src_ip', 'username', 'password', 'status']
        st.dataframe(
            filtered_logins[display_login_cols].fillna("N/A"), 
            use_container_width=True,
            height=400,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "node": st.column_config.TextColumn("Node", width="small"),
                "src_ip": st.column_config.TextColumn("Source IP", width="small"),
            }
        )
    else:
        st.info("No credential attempt data found in the database.")

# ==========================================
# TAB 3: MALWARE & COMMANDS
# ==========================================
with tab_files:
    st.header("Malware & Terminal Commands")
    st.markdown("Tracks file transfers, malware payloads, and every command executed in the shell.")
    
    # --- SECTION 1: ALL CAPTURED FILE OBJECTS & DOWNLOADS ---
    st.subheader("All File Transfers & Downloads (By Hash / URL)")
    st.caption("Includes completed transfers (with SHA-256 hashes) as well as attempted download URLs.")
    
    all_downloads = run_query(f"""
        SELECT 
            COALESCE(shasum, url, destfile, 'Unknown Payload') as payload_identifier,
            eventid,
            COUNT(*) as total_attempts,
            COUNT(DISTINCT src_ip) as unique_ips,
            MAX(url) as download_url,
            MAX(destfile) as destination_file,
            MAX(shasum) as sha256_hash,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM events 
        WHERE (
            eventid LIKE '%file_download%' 
            OR eventid LIKE '%file_upload%'
            OR url IS NOT NULL 
            OR shasum IS NOT NULL
        ) {node_where}
        GROUP BY payload_identifier
        ORDER BY total_attempts DESC
    """, node_params)

    if not all_downloads.empty:
        st.dataframe(
            all_downloads.fillna("N/A"), 
            use_container_width=True, 
            hide_index=True,
            column_config={
                "payload_identifier": st.column_config.TextColumn("Payload Hash / Target", width="large"),
                "total_attempts": st.column_config.NumberColumn("Total Attempts"),
                "unique_ips": st.column_config.NumberColumn("Unique Attacker IPs"),
                "download_url": st.column_config.TextColumn("Source URL", width="medium"),
                "destination_file": st.column_config.TextColumn("Local File", width="small"),
                "sha256_hash": st.column_config.TextColumn("SHA-256 Hash", width="medium"),
                "first_seen": st.column_config.TextColumn("First Seen", width="small"),
                "last_seen": st.column_config.TextColumn("Last Seen", width="small")
            }
        )
    else:
        st.info("No explicit file download objects found in the database.")

    st.divider()

    # --- SECTION 2: ALL ATTACKER TERMINAL COMMANDS ---
    st.subheader("All Attacker Terminal Commands")
    st.caption("A chronological log of every command executed by attackers within the honeypot shell.")
    
    cmd_events = run_query(f"""
        SELECT timestamp, node, src_ip, session, input 
        FROM events 
        WHERE eventid = 'cowrie.command.input' {node_where}
        ORDER BY id
    """, node_params)
    
    if not cmd_events.empty:
        cmd_search = st.text_input("Search Terminal Commands (e.g., uname, rm, cat, wget):", "")
        if cmd_search:
            cmd_events = cmd_events[cmd_events['input'].astype(str).str.lower().str.contains(cmd_search.lower())]
            
        st.dataframe(
            cmd_events.fillna("N/A"), 
            use_container_width=True, 
            height=400,
            hide_index=True,
            column_config={
                "input": st.column_config.TextColumn("Attacker Command", width="large"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "src_ip": st.column_config.TextColumn("Attacker IP", width="small"),
                "session": st.column_config.TextColumn("Session ID", width="small")
            }
        )
    else:
        st.info("No terminal commands found in the database.")
        
# --- SECTION 3: VIRUSTOTAL THREAT INTELLIGENCE ---
    st.divider()
    st.subheader("VirusTotal Search for Captured SHA-256 Hashes")
    
    # Query the database for any captured SHA-256 hashes
    hash_df = run_query(f"SELECT DISTINCT shasum FROM events WHERE shasum IS NOT NULL {node_where}", node_params)
    
    if not hash_df.empty:
        available_hashes = hash_df['shasum'].tolist()
        
        with st.form(key="virustotal_form"):
            vt_api_key = st.text_input("Enter VirusTotal API Key:", type="password", help="Get a free key from virustotal.com")
            selected_hash = st.selectbox("Select a captured SHA-256 hash:", options=available_hashes)
            analyze_btn = st.form_submit_button("Analyze Malware Behavior", use_container_width=True)
            
        if analyze_btn:
            if not vt_api_key:
                st.error("Please enter a VirusTotal API Key.")
            else:
                with st.spinner("Analyzing malware behavior via VirusTotal API v3..."):
                    url = f"https://www.virustotal.com/api/v3/files/{selected_hash}"
                    headers = {"x-apikey": vt_api_key}
                    
                    try:
                        response = requests.get(url, headers=headers)
                        
                        if response.status_code == 200:
                            attr = response.json().get('data', {}).get('attributes', {})
                            
                            stats = attr.get('last_analysis_stats', {})
                            malicious = stats.get('malicious', 0)
                            total_engines = sum(stats.values())
                            
                            # 1. High-Level Metrics
                            st.success(f"**Analysis Complete:** Flagged as malicious by {malicious} out of {total_engines} security vendors.")
                            
                            m1, m2, m3, m4 = st.columns(4)
                            m1.metric("Malicious Flags", malicious)
                            m2.metric("Suspicious Flags", stats.get('suspicious', 0))
                            m3.metric("Undetected", stats.get('undetected', 0))
                            
                            file_size_kb = round(attr.get('size', 0) / 1024, 1)
                            m4.metric("File Size", f"{file_size_kb} KB")
                            
                            st.divider()
                            
                            # 2. MALWARE BEHAVIOR EXPLANATION
                            st.subheader("What This Malware Does")
                            
                            # Extract threat categories and tags
                            threat_class = attr.get('popular_threat_classification', {})
                            suggested_label = threat_class.get('suggested_threat_label', 'Unknown Payload')
                            categories_raw = threat_class.get('popular_threat_category', [])
                            categories = [c.get('value').lower() for c in categories_raw if 'value' in c]
                            
                            tags = [t.lower() for t in attr.get('tags', [])]
                            type_desc = attr.get('type_description', 'Binary executable')
                            
                            # Construct human-readable explanations based on extracted metadata
                            explanations = []
                            
                            if any(c in ['botnet', 'trojan'] for c in categories) or any(t in ['mirai', 'gafgyt', 'tsunami', 'kaiten'] for t in tags):
                                explanations.append("**Botnet Enrolment & DDoS:** This payload recruits the compromised node into an automated botnet. It opens persistent command-and-control channels to launch Distributed Denial-of-Service (DDoS) attacks and aggressively scan adjacent network ranges.")
                                
                            if any(c in ['miner', 'coinminer'] for c in categories) or any(t in ['miner', 'xmrig', 'cryptonight'] for t in tags):
                                explanations.append("**Unauthorized Cryptomining:** This executable steals host system hardware resources to secretly mine cryptocurrency back to the attacker's wallet.")
                                
                            if any(c in ['downloader', 'dropper'] for c in categories) or any(t in ['downloader', 'dropper'] for t in tags):
                                explanations.append("**Secondary Payload Downloader:** This script/binary acts as a stage-1 downloader designed to fetch and execute additional malicious shell scripts, rootkits, or backdoors from remote HTTP/FTP servers.")
                                
                            if any(c in ['worm', 'spreader'] for c in categories) or any(t in ['spreader', 'worm', 'autorun'] for t in tags):
                                explanations.append("**Self-Propagation / Worm Behavior:** Actively scans for open SSH/Telnet ports across public Subnets and attempts dictionary/brute-force attacks to self-replicate onto secondary targets.")
                                
                            if any(c in ['backdoor', 'rat'] for c in categories) or any(t in ['backdoor', 'rat', 'reverse-shell'] for t in tags):
                                explanations.append("**Remote Access Backdoor:** Grants remote attackers an unencrypted reverse-shell or administrative access, bypassing standard host authentication.")
                                
                            # Fallback if specific category signatures aren't triggered
                            if not explanations:
                                explanations.append(f"**Generic Suspicious Payload (`{suggested_label}`):** Performs unauthorized system interactions or binary modifications consistent with automated exploitation toolkits.")

                            # Render the behavioral summary in an info box
                            for exp in explanations:
                                st.info(exp)
                                
                            # 3. Technical Metadata Details
                            st.markdown("#### Technical Metadata")
                            col_t1, col_t2 = st.columns(2)
                            with col_t1:
                                st.markdown(f"**Threat Classification Label:** `{suggested_label}`")
                                st.markdown(f"**File Type / Architecture:** `{type_desc}`")
                            with col_t2:
                                st.markdown(f"**Behavioral Tags:** {', '.join([f'`{t}`' for t in tags[:8]]) if tags else 'None'}")
                                st.markdown(f"[Open Full Vendor Analysis on VirusTotal](https://www.virustotal.com/gui/file/{selected_hash})")
                            
                        elif response.status_code == 404:
                            st.warning("**Unrecognized Payload / Zero-Day:** This hash was not found in VirusTotal's database. This indicates the attacker compiled a custom script or deployed an unindexed payload.")
                        elif response.status_code == 401:
                            st.error("Invalid API Key. Please verify your VirusTotal API key.")
                        elif response.status_code == 429:
                            st.warning("Rate limit reached (4 requests/min on public free tier). Please wait a moment before trying another hash.")
                        else:
                            st.error(f"Failed to connect. HTTP Status Code: {response.status_code}")
                            
                    except Exception as e:
                        st.error(f"Error querying VirusTotal API: {e}")
    else:
        st.info("No SHA-256 hashes found in your database yet.")

# ==========================================
# TAB 4: PROXY & TUNNELING
# ==========================================
with tab_network:
    st.header("SSH Port Forwarding & Proxy Attempts")
    st.markdown("Attackers attempt to use compromised nodes to bounce traffic to external targets. These logs capture direct TCP/IP forward requests.")
    
    proxy_events = run_query(f"""
        SELECT timestamp, node, src_ip, session, dst_ip, dst_port, data 
        FROM events 
        WHERE eventid IN ('cowrie.direct-tcpip.request', 'cowrie.direct-tcpip.data') {node_where}
        ORDER BY id DESC
    """, node_params)
    
    if not proxy_events.empty:
        # Universal search bar for proxy events
        proxy_search = st.text_input("Search Proxy Logs (e.g., Target IP, Port, or Payload snippet):", "")
        
        if proxy_search:
            q = proxy_search.lower()
            # This mask searches across every column in the dataframe simultaneously
            mask = proxy_events.astype(str).apply(lambda x: x.str.lower().str.contains(q).any(), axis=1)
            proxy_events = proxy_events[mask]

        st.write(f"Showing **{len(proxy_events):,}** proxy/tunneling logs:")
        
        proxy_events = proxy_events.dropna(axis=1, how='all')
        st.dataframe(
            proxy_events.fillna("N/A"), 
            use_container_width=True, 
            hide_index=True,
            column_config={
                "data": st.column_config.TextColumn("Raw Payload", width="large"),
                "dst_ip": st.column_config.TextColumn("Target IP", width="small"),
                "dst_port": st.column_config.NumberColumn("Target Port")
            }
        )
    else:
        st.info("No proxy or port forwarding attempts found in the database.")

# ==========================================
# TAB 5: CATCH-ALL EVENT EXPLORER
# ==========================================
with tab_explorer:
    st.header("Raw Event Explorer")
    st.markdown("Inspect every event captured by Cowrie. Unpacks the original raw JSON string directly from the database to ensure nothing is lost.")
    
    events_list_df = run_query(f"SELECT DISTINCT eventid FROM events WHERE eventid IS NOT NULL {node_where}", node_params)
    
    if not events_list_df.empty:
        unique_events = sorted(events_list_df['eventid'].dropna().tolist())
        selected_event = st.selectbox("Select a Cowrie Event Type to Explore:", options=unique_events)
        
        # Pull raw JSON payloads for selected event
        explorer_raw = run_query(f"""
            SELECT raw_json 
            FROM events 
            WHERE eventid = ? {node_where} 
            ORDER BY id DESC 
            LIMIT 500
        """, tuple([selected_event] + list(node_params)))
        
        if not explorer_raw.empty:
            unpacked_rows = []
            for item in explorer_raw['raw_json']:
                try:
                    unpacked_rows.append(json.loads(item))
                except (json.JSONDecodeError, TypeError):
                    continue
                    
            dynamic_df = pd.DataFrame(unpacked_rows)
            st.write(f"Showing the latest **{len(dynamic_df):,}** fully-unpacked records for `{selected_event}`:")
            st.dataframe(dynamic_df.fillna("N/A"), use_container_width=True, hide_index=True)
        else:
            st.info(f"No records found for event: `{selected_event}`")
    else:
        st.info("No events found in the database.")
        
# ==========================================
# TAB 6: ATTACKER TIMELINE
# ==========================================
import json

with tab_timeline:
    st.header("Reconstruct an Attack Session")
    st.markdown("Paste a `session` ID here to see a chronological timeline of every single action the attacker took. This view unpacks the raw JSON payload to ensure absolutely zero metadata is hidden.")
    
    # Show more context in the "Most Active" table
    top_sessions = run_query(f"""
        SELECT session, COUNT(*) as action_count, src_ip, MIN(timestamp) as start_time
        FROM events 
        WHERE session IS NOT NULL {node_where} 
        GROUP BY session 
        ORDER BY action_count DESC 
        LIMIT 5
    """, node_params)
    
    st.write("**Most Active Sessions (Click to copy ID):**")
    st.dataframe(top_sessions, hide_index=True)
    
    target_session = st.text_input("Enter Session ID to investigate:", "")
    
    if target_session:
        # Pull the raw_json instead of hardcoded columns
        timeline_raw = run_query(f"""
            SELECT raw_json 
            FROM events 
            WHERE session = ? {node_where}
            ORDER BY timestamp ASC
        """, tuple([target_session] + list(node_params)))
        
        if not timeline_raw.empty:
            st.success(f"Found {len(timeline_raw)} discrete actions for session `{target_session}`")
            
            # Unpack the raw JSON dynamically
            unpacked_rows = []
            for item in timeline_raw['raw_json']:
                try:
                    unpacked_rows.append(json.loads(item))
                except (json.JSONDecodeError, TypeError):
                    continue
                    
            timeline_df = pd.DataFrame(unpacked_rows)
            
            # Reorganize the columns so the most important ones are on the left, 
            # and the obscure/dynamic ones get pushed to the right.
            preferred_order = ['timestamp', 'eventid', 'src_ip', 'username', 'password', 'input', 'url', 'destfile', 'shasum', 'dst_ip', 'dst_port', 'data']
            
            front_cols = [c for c in preferred_order if c in timeline_df.columns]
            back_cols = [c for c in timeline_df.columns if c not in front_cols]
            
            timeline_df = timeline_df[front_cols + back_cols]
            
            # Drop any columns that are entirely empty for this specific session
            timeline_clean = timeline_df.dropna(axis=1, how='all')
            
            st.dataframe(
                timeline_clean.fillna(""), 
                use_container_width=True, 
                hide_index=True
            )
        else:
            st.warning("No data found for that session ID.")