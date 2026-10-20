# check_db_tables.py
# Run this on your laptop

import psycopg2
import os
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv("POSTGRES_HOST", "")

if not DATABASE_URL:
    print("ERROR: DATABASE_URL not in .env")
    print("Ask Person A for the PostgreSQL connection string")
    exit(1)

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    # Check which tables exist
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    
    tables = [row[0] for row in cur.fetchall()]
    print(f"Tables found: {tables}")
    
    required_tables = [
        "eval_results",
        "metrics", 
        "healing_events",
        "recommendations"
    ]
    
    for table in required_tables:
        if table in tables:
            print(f"✅ {table} exists")
        else:
            print(f"❌ {table} MISSING — ask Person A to create it")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"Cannot connect to PostgreSQL: {e}")
    print("Check DATABASE_URL and ask Person A if PostgreSQL is running")