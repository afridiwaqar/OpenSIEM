#!/usr/bin/python3

# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import requests
import psycopg2
import configparser
import logging
import time
from datetime import datetime
import schedule
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('keyword_updater.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('/etc/opensiem/opensiem.conf')
db_config = config['database']

# Need to add my own source here
_DEFAULT_SOURCE = 'https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/master/only_keywords.txt'

def _load_sources() -> list[str]:
    try:
        raw = config['artifacts']['sources']
        urls = [u.strip() for u in raw.replace('\n', ',').split(',') if u.strip()]
        if urls:
            return urls
    except (KeyError, configparser.Error):
        pass
    return [_DEFAULT_SOURCE]

KEYWORD_SOURCES = _load_sources()

def establish_connection():
    print("\n" + "="*60)
    print("DATABASE CONNECTION STATUS")
    print("="*60)
    print(f"Host: {db_config['host']}")
    print(f"Database: {db_config['database']}")
    print(f"User: {db_config['user']}")
    print("-" * 40)
    
    print("Attempting to connect to database...", end=" ", flush=True)
    
    try:
        conn = psycopg2.connect(
            host=db_config['host'],
            database=db_config['database'],
            user=db_config['user'],
            password=db_config['password'],
            connect_timeout=10
        )
        print("SUCCESS!")
        print(f"Database connection established")
        return conn
    except psycopg2.OperationalError as e:
        print("FAILED!")
        print(f"\nDatabase connection error: {e}")
        print("\nTroubleshooting tips:")
        print("Check if PostgreSQL service is running")
        print("Verify database credentials in opensiem.conf")
        print("Ensure database exists and is accessible")
        print("Check network connectivity to database host")
        logger.error(f"Database connection failed: {e}")
        return None
    except Exception as e:
        print("FAILED!")
        print(f"\nUnexpected error: {e}")
        logger.error(f"Database connection failed: {e}")
        return None

def clean_keyword(keyword):
    if not keyword or not keyword.strip():
        return None
    
    kw = keyword.strip()    
    if kw.startswith("*") and kw.endswith("*"):
        kw = kw[1:-1]

    kw = kw.replace("*", '"')    
    kw = ' '.join(kw.split())
    
    return kw if kw else None

def estimate_severity(keyword):
    keyword_lower = keyword.lower()
    
    high_indicators = [
        'exploit', '0day', 'zero-day', 'backdoor', 'rootkit', 
        'ransomware', 'rat', 'botnet', 'c2', 'command and control',
        'privilege escalation', 'privileged', 'admin', 'root',
        'bypass', 'evasion', 'persistence', 'lateral movement',
        'exfiltration', 'data theft', 'credential dumping'
    ]
    
    mid_indicators = [
        'malware', 'trojan', 'worm', 'virus', 'spyware',
        'keylogger', 'stealer', 'injector', 'dropper',
        'payload', 'shellcode', 'obfuscation', 'encoded',
        'suspicious', 'anomalous', 'unusual', 'atypical'
    ]
    
    for indicator in high_indicators:
        if indicator in keyword_lower:
            return 'high'
    
    for indicator in mid_indicators:
        if indicator in keyword_lower:
            return 'mid'
    
    return 'low'

def fetch_keywords_from_source(url: str) -> list[str]:
    print(f"\n{'='*60}")
    print(f"FETCHING FROM SOURCE")
    print(f"{'='*60}")
    print(f"URL: {url}")
    print("-" * 40)
    print("Connecting...", end=" ", flush=True)

    try:
        response = requests.get(url, timeout=30, stream=True)

        if response.status_code == 200:
            print("CONNECTED!")
            print(f"HTTP Status: {response.status_code} OK")

            content_length = response.headers.get('content-length')
            if content_length:
                print(f"Expected size: {int(content_length):,} bytes")

            print("\nDownloading...")
            content = ""
            chunk_count = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if chunk:
                    content += chunk
                    chunk_count += 1
                    if chunk_count % 10 == 0:
                        print(f"   Downloaded {len(content):,} bytes so far...", end="\r", flush=True)

            print(f"Downloaded {len(content):,} bytes total")

            raw_keywords = content.splitlines()
            total_raw = len(raw_keywords)
            print(f"Raw lines: {total_raw:,}")

            print("\nCleaning keywords...")
            cleaned = []
            invalid = 0
            for i, kw in enumerate(raw_keywords):
                c = clean_keyword(kw)
                if c:
                    cleaned.append(c)
                else:
                    invalid += 1
                if (i + 1) % 1000 == 0:
                    print(f"   Processed {i+1:,}/{total_raw:,}...")

            print(f"\nResult: {len(cleaned):,} valid, {invalid:,} skipped")
            logger.info(f"Fetched {len(cleaned)} keywords from {url}")
            return cleaned

        else:
            print(f"HTTP {response.status_code} — {response.reason}")
            logger.warning(f"Failed to fetch from {url}: HTTP {response.status_code}")
            return []

    except requests.ConnectionError:
        print("Connection error — could not reach host")
        logger.error(f"Connection error fetching from {url}")
        return []
    except requests.Timeout:
        print("Timeout — host took too long to respond")
        logger.error(f"Timeout fetching from {url}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        logger.error(f"Error fetching from {url}: {e}")
        return []


def fetch_keywords_from_all_sources() -> list[str]:

    for i, url in enumerate(KEYWORD_SOURCES, 1):
        print(f"  {i}. {url}")

    seen: set[str] = set()
    merged: list[str] = []

    for url in KEYWORD_SOURCES:
        batch = fetch_keywords_from_source(url)
        new_count = 0
        for kw in batch:
            if kw not in seen:
                seen.add(kw)
                merged.append(kw)
                new_count += 1
        print(f"{new_count:,} unique keywords from this source")

    print(f"\nTotal unique keywords across all sources: {len(merged):,}")
    logger.info(f"Merged {len(merged)} unique keywords from {len(KEYWORD_SOURCES)} source(s)")
    return merged

def update_database_with_keywords(keywords: list[str], source_url: str = 'merged'):

    if not keywords:
        print("\nNo keywords to insert")
        return 0

    print(f"\n{'='*60}")
    print("DATABASE UPDATE STATUS")
    print(f"{'='*60}")

    conn = establish_connection()
    if not conn:
        return 0

    inserted_count  = 0
    duplicate_count = 0
    error_count     = 0
    severity_counts = {'low': 0, 'mid': 0, 'high': 0}

    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM malicious_artifacts")
        total_before = cur.fetchone()[0]
        print(f"Records before update: {total_before:,}")

        insert_query = """
        INSERT INTO malicious_artifacts (artifacts, severity, source_url, added_at)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (artifacts) DO NOTHING
        RETURNING artifacts;
        """

        current_time = datetime.now()
        print("\nInserting new keywords (skipping existing)...")

        for i, keyword in enumerate(keywords):
            try:
                severity = estimate_severity(keyword)
                severity_counts[severity] += 1

                cur.execute(insert_query, (keyword, severity, source_url, current_time))
                if cur.fetchone():
                    inserted_count += 1
                else:
                    duplicate_count += 1

            except Exception as e:
                error_count += 1
                if error_count <= 5:
                    logger.warning(f"Error inserting '{keyword[:50]}': {e}")

            if (i + 1) % 100 == 0:
                print(f"   Processed {i+1:,}/{len(keywords):,}...")

        conn.commit()

        print(f"\nUpdate complete:")
        print(f"New keywords inserted : {inserted_count:,}")
        print(f"Already existed (kept): {duplicate_count:,}")
        print(f"Errors               : {error_count:,}")
        print(f"\n Severity breakdown of new inserts:")
        print(f"   🔴 High  : {severity_counts['high']:,}")
        print(f"   🟡 Medium: {severity_counts['mid']:,}")
        print(f"   🟢 Low   : {severity_counts['low']:,}")

        cur.execute("SELECT COUNT(*) FROM malicious_artifacts")
        total_after = cur.fetchone()[0]
        print(f"\n{total_before:,} → {total_after:,} records (+{total_after - total_before})")

        logger.info(f"Inserted {inserted_count} new, skipped {duplicate_count} existing")

    except Exception as e:
        print(f"\nDatabase error: {e}")
        logger.error(f"Database error: {e}")
        conn.rollback()
        return 0
    finally:
        cur.close()
        conn.close()

    return inserted_count

def perform_keyword_update():
    print("\n" + "O"*30)
    print("O MALICIOUS KEYWORDS UPDATER")
    print("O"*30)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Sources configured: {len(KEYWORD_SOURCES)}")

    logger.info("="*60)
    logger.info("Starting keyword update process")
    logger.info("="*60)

    keywords = fetch_keywords_from_all_sources()

    if keywords:
        total_inserted = update_database_with_keywords(keywords, source_url='multi-source')
        print(f"\n Update completed — {total_inserted:,} new keywords added.")
    else:
        total_inserted = 0
        print("\n Update failed — no keywords fetched from any source.")

    print(f"\n Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("O"*30)

    return total_inserted


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='OpenSIEM Malicious Keywords Updater — fetches IOC keywords '
                    'from all sources configured in opensiem.conf [artifacts] section '
                    'and inserts any new ones into malicious_artifacts. '
                    'Existing keywords (including admin-added ones) are never removed.'
    )
    parser.add_argument('--mode', choices=['once', 'schedule', 'force'],
                        default='once', help='Run mode (default: once)')

    args = parser.parse_args()

    print("\n Configuration:")
    print(f"  Mode   : {args.mode}")
    print(f"  Sources: {len(KEYWORD_SOURCES)}")
    for i, url in enumerate(KEYWORD_SOURCES, 1):
        print(f"    {i}. {url}")
    print()

    if args.mode in ('once', 'force'):
        perform_keyword_update()

    elif args.mode == 'schedule':
        print(" Starting scheduled keyword updater...")
        print("   Will run daily at 02:00 AM")
        print("   Press Ctrl+C to stop\n")

        schedule.every().day.at("02:00").do(perform_keyword_update)

        perform_keyword_update()

        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
                print(f"\r Waiting for next scheduled run... {datetime.now().strftime('%H:%M:%S')}",
                      end="", flush=True)
        except KeyboardInterrupt:
            print("\n\n Shutting down keyword updater...")



if __name__ == "__main__":
    print("\n" + "="*60)
    print(" INITIAL SETUP")
    print("="*60)
    
    conn = establish_connection()
    if conn:
        cur = conn.cursor()
        try:
            print(" Creating/verifying database table...")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS malicious_artifacts (
                artifacts TEXT PRIMARY KEY,
                "interval" INTEGER DEFAULT 0,
                severity VARCHAR(10) DEFAULT 'mid' CHECK (severity IN ('low', 'mid', 'high')),
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_url VARCHAR(500)
            );
            """)
            
            cur.execute("""
            DO $$ 
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'unique_artifact') THEN
                    ALTER TABLE malicious_artifacts ADD CONSTRAINT unique_artifact UNIQUE (artifacts);
                END IF;
            END $$;
            """)
            
            conn.commit()
            print("Database table malicious_artifacts is ready")
            
            cur.execute("SELECT COUNT(*) FROM malicious_artifacts")
            count = cur.fetchone()[0]
            print(f"Current records: {count:,}")
            
            if count > 0:
                cur.execute("SELECT severity, COUNT(*) FROM malicious_artifacts GROUP BY severity")
                sev_counts = cur.fetchall()
                for severity, sev_count in sev_counts:
                    sev_icon = "🔴" if severity == "high" else "🟡" if severity == "mid" else "🟢"
                    print(f"   {sev_icon} {severity.capitalize()}: {sev_count:,}")
            
        except Exception as e:
            print(f" Database setup error: {e}")
            logger.error(f"Database setup error: {e}")
        finally:
            cur.close()
            conn.close()
    
    print()
    main()
