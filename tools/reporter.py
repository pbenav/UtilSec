#!/usr/bin/env python3
import sqlite3
import os
import sys
from datetime import datetime, timedelta

def generate_html_report(db_path, output_path, days=7):
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    since_ts = (datetime.now() - timedelta(days=days)).timestamp()
    
    c.execute("SELECT count(*) FROM events WHERE timestamp >= ?", (since_ts,))
    total_attacks = c.fetchone()[0]
    
    c.execute("SELECT count(*) FROM bans WHERE banned_at >= ?", (since_ts,))
    total_bans = c.fetchone()[0]
    
    c.execute("SELECT country, count(*) as c FROM events WHERE timestamp >= ? GROUP BY country ORDER BY c DESC LIMIT 10", (since_ts,))
    top_countries = c.fetchall()
    
    c.execute("SELECT ip, count(*) as c, country FROM events WHERE timestamp >= ? GROUP BY ip ORDER BY c DESC LIMIT 10", (since_ts,))
    top_ips = c.fetchall()

    c.execute("SELECT matched_rule, count(*) as c FROM events WHERE timestamp >= ? GROUP BY matched_rule ORDER BY c DESC LIMIT 10", (since_ts,))
    top_rules = c.fetchall()

    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>UtilSec Security Report</title>
        <style>
            body {{ font-family: -apple-system, system-ui, sans-serif; background: #f4f4f9; color: #333; margin: 40px; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; text-align: center; }}
            .card h2 {{ margin: 0; font-size: 36px; color: #e74c3c; }}
            .card p {{ margin: 5px 0 0; color: #7f8c8d; text-transform: uppercase; font-size: 12px; font-weight: bold; }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #34495e; color: #fff; }}
            tr:last-child td {{ border-bottom: none; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            h3 {{ color: #34495e; margin-top: 0; }}
            .table-container {{ padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <h1>UtilSec Security Report</h1>
        <p><strong>Period:</strong> Last {days} days (Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")})</p>
        
        <div class="summary">
            <div class="card">
                <h2>{total_attacks:,}</h2>
                <p>Total Attacks Prevented</p>
            </div>
            <div class="card">
                <h2>{total_bans:,}</h2>
                <p>Total IP Bans Issued</p>
            </div>
        </div>
        
        <div class="grid">
            <div class="table-container">
                <h3>Top Attacking Countries</h3>
                <table>
                    <tr><th>Country</th><th>Attacks</th></tr>
                    {"".join(f"<tr><td>{country}</td><td>{count:,}</td></tr>" for country, count in top_countries)}
                </table>
            </div>
            
            <div class="table-container">
                <h3>Top Attacking IPs</h3>
                <table>
                    <tr><th>IP</th><th>Country</th><th>Attacks</th></tr>
                    {"".join(f"<tr><td>{ip}</td><td>{country}</td><td>{count:,}</td></tr>" for ip, count, country in top_ips)}
                </table>
            </div>
            
            <div class="table-container" style="grid-column: 1 / -1;">
                <h3>Most Triggered Firewall Rules</h3>
                <table>
                    <tr><th>Rule Triggered</th><th>Hits</th></tr>
                    {"".join(f"<tr><td>{rule}</td><td>{count:,}</td></tr>" for rule, count in top_rules)}
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Report successfully generated at: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db = os.path.join(base_dir, "sentinel_history.db")
    out = os.path.join(base_dir, "report.html")
    generate_html_report(db, out, days=7)
