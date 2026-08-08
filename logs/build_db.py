import os
import sys
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# 1. SPECIFY YOUR LOG FILES HERE
# -----------------------------------------------------------------------------
FILES_TO_PROCESS = [
    "goofy-cowrie.json",
    "pluto-cowrie.json",
    "mickey-cowrie.json"
]

# Define your geography mapping for nodes
node_GEO_MAP = {
    "goofy": "America",
    "pluto": "Europe",
    "mickey": "Asia",
}

DB_FILE = "honeypot.db"

# -----------------------------------------------------------------------------
# 2. DATABASE SETUP
# -----------------------------------------------------------------------------
def create_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Using 'event_hash TEXT UNIQUE' to prevent duplicate insertions
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT UNIQUE,
            timestamp TEXT,
            node TEXT,
            eventid TEXT,
            session TEXT,
            src_ip TEXT,
            username TEXT,
            password TEXT,
            input TEXT,
            url TEXT,
            destfile TEXT,
            shasum TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            data TEXT,
            raw_json TEXT
        )
    ''')
    
    c.execute("CREATE INDEX IF NOT EXISTS idx_eventid ON events(eventid);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_session ON events(session);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip);")
    conn.commit()
    return conn

# -----------------------------------------------------------------------------
# 3. INGESTION LOGIC
# -----------------------------------------------------------------------------
def import_json_files(conn, target_files):
    c = conn.cursor()
    
    # Filter out files that don't exist
    valid_files = [f for f in target_files if os.path.exists(f)]
    missing_files = [f for f in target_files if not os.path.exists(f)]
    
    if missing_files:
        print("Warning: The following specified files were not found:")
        for mf in missing_files:
            print(f"   - {mf}")
        print()
        
    if not valid_files:
        print("No valid target files to process. Exiting.")
        return

    print(f"Processing {len(valid_files)} specified file(s): {valid_files}\n")
    
    total_new_inserted = 0
    batch_size = 50000

    for file_path in valid_files:
        print(f"Processing: {file_path} ...")
        batch = []
        file_inserted_count = 0
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Handle WalT-formatted logs and raw Cowrie logs
                if " -> " in line:
                    json_str = line.split(" -> ", 1)[1].strip()
                elif line.startswith("{"):
                    json_str = line
                else:
                    continue  
                    
                try:
                    data = json.loads(json_str)
                    
                    # 1. Create a unique hash of the payload
                    event_hash = hashlib.md5(json_str.encode('utf-8')).hexdigest()
                    
                    # 2. Map Geography
                    node = data.get('sensor') 
                    if node in node_GEO_MAP:
                        node = f"{node} ({node_GEO_MAP[node]})"
                        
                    # 3. Fast Timezone Conversion
                    ts = data.get('timestamp')
                    if ts:
                        try:
                            dt_obj = datetime.fromisoformat(ts.replace('Z', ''))
                            local_dt = dt_obj + timedelta(hours=3)
                            ts = local_dt.strftime('%Y-%m-%d %H:%M:%S (UTC+3)')
                        except Exception:
                            pass 
                    
                    batch.append((
                        event_hash,
                        ts,
                        node,
                        data.get('eventid'),
                        data.get('session'),
                        data.get('src_ip'),
                        data.get('username'),
                        data.get('password'),
                        data.get('input'),
                        data.get('url'),
                        data.get('destfile'),
                        data.get('shasum'),
                        data.get('dst_ip'),
                        data.get('dst_port'),
                        str(data.get('data')) if 'data' in data else None,
                        json_str 
                    ))
                    
                    if len(batch) >= batch_size:
                        c.executemany('''
                            INSERT OR IGNORE INTO events 
                            (event_hash, timestamp, node, eventid, session, src_ip, username, password, input, url, destfile, shasum, dst_ip, dst_port, data, raw_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', batch)
                        file_inserted_count += c.rowcount
                        conn.commit()
                        batch = []
                        
                except json.JSONDecodeError:
                    continue

            # Process remaining items
            if batch:
                c.executemany('''
                    INSERT OR IGNORE INTO events 
                    (event_hash, timestamp, node, eventid, session, src_ip, username, password, input, url, destfile, shasum, dst_ip, dst_port, data, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', batch)
                file_inserted_count += c.rowcount
                conn.commit()
                
        print(f"   ↳ Added {file_inserted_count:,} new events from {file_path}")
        total_new_inserted += file_inserted_count

    print(f"\nTotal NEW events added across all files: {total_new_inserted:,}")
    conn.close()

if __name__ == "__main__":
    db_conn = create_database()
    
    # If file arguments are passed via terminal, use them; otherwise default to FILES_TO_PROCESS
    if len(sys.argv) > 1:
        target_list = sys.argv[1:]
    else:
        target_list = FILES_TO_PROCESS
        
    import_json_files(db_conn, target_list)