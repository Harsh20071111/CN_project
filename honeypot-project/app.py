from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import datetime
import requests
import csv
import smtplib
from email.mime.text import MIMEText
import os

app = Flask(__name__)
app.secret_key = "super_secure_admin_key"

DB_NAME = 'logs_advanced.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            ip TEXT,
            location TEXT,
            risk_level TEXT,
            time TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_location(ip):
    try:
        # Avoid hitting API for local IP during testing
        if ip in ['127.0.0.1', '::1', 'localhost']:
            return 'Localhost', 'N/A'
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if res.status_code == 200:
            data = res.json()
            city = data.get('city', 'Unknown')
            country = data.get('country', 'Unknown')
            lat = data.get('lat')
            lon = data.get('lon')
            location_text = f"{city}, {country}"
            maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "N/A"
            return location_text, maps_link
    except Exception:
        pass
    return "Unknown", "N/A"

def detect_attack(username, password):
    # Rule-based Basic AI / Heuristics for detection
    username = username.lower()
    if username == "admin" or password == "123456" or "root" in username or password.lower() == "password":
        return "High Risk"
    return "Normal"

def send_email_alert(ip, username, password, location, maps_link, time):
    sender = "kamleshpanchal21121983@gmail.com"
    app_password = "flbx qviu oqgg kfnl"

    message = f"""
    🚨 Honeypot Alert!

    IP Address: {ip}
    Location: {location}
    Live Map: {maps_link}
    Username: {username}
    Password: {password}
    Time: {time}
    """

    msg = MIMEText(message)
    msg['Subject'] = "Honeypot Alert - Attack Detected"
    msg['From'] = sender
    msg['To'] = sender

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, app_password)
        server.send_message(msg)
        server.quit()
        print("Email sent!")
    except Exception as e:
        print("Email error:", e)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Get Real IP behind Render's reverse proxy
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
        
    time_str = str(datetime.datetime.now())

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Enriched Data
    location_text, maps_link = get_location(ip)
    
    # Override with EXACT GPS if the browser allowed it
    exact_lat = request.form.get('exact_lat')
    exact_lon = request.form.get('exact_lon')
    if exact_lat and exact_lon:
        maps_link = f"https://www.google.com/maps?q={exact_lat},{exact_lon}"
        location_text += " (EXACT GPS MATCH)"
    risk_level = detect_attack(username, password)

    # Save to Database (we log every attempt to keep history, even if blocked)
    c.execute("INSERT INTO logs (username, password, ip, location, risk_level, time) VALUES (?, ?, ?, ?, ?, ?)",
              (username, password, ip, location_text, risk_level, time_str))
    conn.commit()

    # Check Username Blocking System
    c.execute("SELECT COUNT(*) FROM logs WHERE ip = ? AND username = ?", (ip, username))
    attempts = c.fetchone()[0]
    conn.close()

    # Alert System: ONLY send an email when the attacker gets blocked (on the 6th attempt)
    # This prevents email spam for just 1 or 2 mistakes.
    if attempts == 6:
        send_email_alert(ip, username, password, location_text, maps_link, time_str)

    if attempts > 5:
        return f"Access Denied. The username '{username}' has been temporarily blocked due to excessive login attempts.", 403

    return "Login Failed. Invalid credentials."

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login_page():
    if request.method == 'POST':
        # Admin Protection Login
        if request.form.get('password') == "admin123":
            session['admin'] = True
            return redirect('/dashboard')
        else:
            return "Invalid admin password.", 401
    return render_template('admin_login.html')

@app.route('/dashboard')
def dashboard():
    # Admin session check
    if not session.get('admin'):
        return redirect('/admin_login')

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    return render_template('dashboard.html', logs=data)

@app.route('/export')
def export():
    # Export Logs (CSV)
    if not session.get('admin'):
        return redirect('/admin_login')
        
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    csv_path = 'logs.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Username', 'Password', 'IP', 'Location', 'Risk Level', 'Time'])
        writer.writerows(data)

    return send_file(csv_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect('/admin_login')

@app.route('/blocked_accounts')
def blocked_accounts():
    """Return JSON list of all blocked IP+username combos."""
    if not session.get('admin'):
        return {'error': 'Unauthorized'}, 401
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        SELECT ip, username, COUNT(*) as attempts
        FROM logs
        GROUP BY ip, username
        HAVING COUNT(*) > 5
        ORDER BY attempts DESC
    """)
    rows = c.fetchall()
    conn.close()
    blocked = [{'ip': r[0], 'username': r[1], 'attempts': r[2]} for r in rows]
    return {'blocked': blocked}

@app.route('/unblock', methods=['POST'])
def unblock():
    """Unblock an account by deleting its log entries."""
    if not session.get('admin'):
        return {'error': 'Unauthorized'}, 401
    
    from flask import jsonify
    ip = request.form.get('ip', '')
    username = request.form.get('username', '')

    if not ip or not username:
        return {'error': 'IP and username are required'}, 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE ip = ? AND username = ?", (ip, username))
    deleted = c.rowcount
    conn.commit()
    conn.close()

    return {'success': True, 'deleted': deleted, 'ip': ip, 'username': username}

@app.route('/clear_local')
def clear_local():
    if not session.get('admin'):
        return redirect('/admin_login')
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE ip LIKE '127.%' OR ip LIKE '10.%' OR ip LIKE '::1' OR ip = 'localhost'")
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return f"Cleared {deleted} localhost/internal entries. <a href='/dashboard'>Go back to Dashboard</a>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
