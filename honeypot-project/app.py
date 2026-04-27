from flask import Flask, render_template, request, redirect, session, send_file, flash
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
import datetime
import requests
import csv
import smtplib
from email.mime.text import MIMEText
import os
import ipaddress

app = Flask(__name__)
app.secret_key = "super_secure_admin_key"

# Fix for Render's reverse proxy — ensures real client IP is captured
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DB_NAME = 'logs_advanced.db'


def normalize_ip(value):
    """Normalize common proxy/IP formats into a single IP string."""
    if not value:
        return ""
    ip = value.strip()
    if "," in ip:
        ip = ip.split(",")[0].strip()
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "", 1)
    return ip


def get_client_ip(req):
    """Get the most reliable client IP from proxy headers/request."""
    forwarded_for = req.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        for candidate in forwarded_for.split(','):
            ip = normalize_ip(candidate)
            if ip and ip.lower() != 'unknown':
                return ip

    real_ip = normalize_ip(req.headers.get('X-Real-IP', ''))
    if real_ip and real_ip.lower() != 'unknown':
        return real_ip

    remote = normalize_ip(req.remote_addr or '')
    return remote if remote else 'Unknown'


def is_local_or_private_ip(ip):
    if ip in ['127.0.0.1', '::1', 'localhost']:
        return True
    try:
        parsed = ipaddress.ip_address(ip)
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
        )
    except ValueError:
        return False


def reverse_geocode(lat, lon):
    """Try to resolve GPS coordinates into a human-readable location."""
    try:
        res = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon},
            headers={"User-Agent": "honeypot-project/1.0"},
            timeout=3,
        )
        if res.status_code == 200:
            data = res.json()
            addr = data.get('address', {})
            city = (
                addr.get('city')
                or addr.get('town')
                or addr.get('village')
                or addr.get('municipality')
                or addr.get('state_district')
                or addr.get('state')
            )
            country = addr.get('country')
            if city and country:
                return f"{city}, {country}"
            if country:
                return country
    except Exception:
        pass
    return None


def format_location(city=None, country=None, region=None):
    if city and country:
        return f"{city}, {country}"
    if region and country:
        return f"{region}, {country}"
    if city:
        return city
    if country:
        return country
    return "Unknown"

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
    
    # Create Real User Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    
    # Add demo user if not exists
    c.execute("SELECT * FROM users WHERE username='harsh'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password) VALUES ('harsh', '1234')")
        
    conn.commit()
    conn.close()

init_db()

def get_location(ip, exact_lat=None, exact_lon=None):
    # If browser gave exact GPS, try reverse geocoding first.
    if exact_lat and exact_lon:
        maps_link = f"https://www.google.com/maps?q={exact_lat},{exact_lon}"
        gps_location = reverse_geocode(exact_lat, exact_lon)
        if gps_location:
            return f"{gps_location} (EXACT GPS MATCH)", maps_link

    try:
        if is_local_or_private_ip(ip):
            if exact_lat and exact_lon:
                return "Private/Local Network (EXACT GPS COORDINATES CAPTURED)", f"https://www.google.com/maps?q={exact_lat},{exact_lon}"
            return 'Private/Local Network', 'N/A'

        # Provider 1: ipapi (HTTPS)
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if res.status_code == 200:
            data = res.json()
            if not data.get('error'):
                city = data.get('city')
                country = data.get('country_name')
                region = data.get('region')
                lat = data.get('latitude')
                lon = data.get('longitude')
                location_text = format_location(city, country, region)
                maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat is not None and lon is not None else "N/A"
                if location_text != 'Unknown':
                    return location_text, maps_link

        # Provider 2 fallback: ip-api
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            if data.get('status') == 'success':
                city = data.get('city')
                country = data.get('country')
                region = data.get('regionName')
                lat = data.get('lat')
                lon = data.get('lon')
                location_text = format_location(city, country, region)
                maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat is not None and lon is not None else "N/A"
                if location_text != 'Unknown':
                    return location_text, maps_link
    except Exception:
        pass

    if exact_lat and exact_lon:
        return "Unknown (EXACT GPS COORDINATES CAPTURED)", f"https://www.google.com/maps?q={exact_lat},{exact_lon}"
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

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Check if user exists at all
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_record = c.fetchone()

        if user_record:
            # User exists, check password
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            user_auth = c.fetchone()
            conn.close()

            if user_auth:
                session['user'] = username
                return redirect('/bank-dashboard')
            else:
                return render_template('bank_login.html', error="Login Failed. Incorrect password. Forgot password?")
        
        # User DOES NOT exist -> Honeypot Logic
        ip = get_client_ip(request)
        time_str = str(datetime.datetime.now())
        exact_lat = request.form.get('exact_lat')
        exact_lon = request.form.get('exact_lon')
        location_text, maps_link = get_location(ip, exact_lat, exact_lon)
        risk_level = detect_attack(username, password)

        c.execute("INSERT INTO logs (username, password, ip, location, risk_level, time) VALUES (?, ?, ?, ?, ?, ?)",
                  (username, password, ip, location_text, risk_level, time_str))
        conn.commit()

        c.execute("SELECT COUNT(*) FROM logs WHERE ip = ? AND username = ?", (ip, username))
        attempts = c.fetchone()[0]
        conn.close()

        if attempts == 5:
            send_email_alert(ip, username, password, location_text, maps_link, time_str)

        if attempts >= 5:
            return f"Access Denied. The username '{username}' has been temporarily blocked due to excessive login attempts.", 403

        return render_template('bank_login.html', error="Invalid credentials")

    return render_template('bank_login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '')
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_record = c.fetchone()
        conn.close()

        if user_record:
            return render_template('forgot_password.html', success="A password reset link has been sent to your registered email.")
        else:
            return render_template('forgot_password.html', error="If this username exists, a reset link was sent.")

    return render_template('forgot_password.html')

@app.route('/bank-dashboard')
def bank_dashboard():
    if not session.get('user'):
        return redirect('/')
    return render_template('bank_dashboard.html')



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
    logs_data = c.fetchall()
    
    c.execute("SELECT * FROM users")
    users_data = c.fetchall()
    conn.close()

    return render_template('dashboard.html', logs=logs_data, users=users_data)

@app.route('/add_user', methods=['POST'])
def add_user():
    # Only authenticated admins can create valid banking users.
    if not session.get('admin'):
        return redirect('/admin_login')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect('/dashboard')

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing_user = c.fetchone()

    if existing_user:
        conn.close()
        flash(f"User '{username}' already exists.", 'error')
        return redirect('/dashboard')

    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

    flash(f"Valid user '{username}' added successfully.", 'success')
    return redirect('/dashboard')

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
        HAVING COUNT(*) >= 5
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
    app.run(debug=True, port=5001)
