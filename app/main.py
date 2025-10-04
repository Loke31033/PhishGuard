import os
import tempfile
import sqlite3
import json
from flask import Flask, request, jsonify, render_template, redirect, url_for
from analyzer import (
    parse_eml,
    extract_urls,
    find_suspicious_keywords,
    classify_risk,
    analyze_url_risk,
    analyze_attachment_risk
)
from backend import check_email_auth  # Live SPF/DKIM/DMARC verification

app = Flask(__name__)

# -------------------------------
# Database setup
# -------------------------------
DB_PATH = 'phishguard.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,  
            receiver TEXT,
            subject TEXT,
            date TEXT,
            risk_level TEXT,
            data TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -------------------------------
# Routes
# -------------------------------
@app.route('/')
def index():
    return '<h2>PhishGuard — Upload .eml file via POST to /upload or visit /dashboard</h2>'

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('email')
    if not f:
        return jsonify({'error': 'No file uploaded'}), 400

    # Save uploaded file temporarily
    temp_path = os.path.join(tempfile.gettempdir(), f.filename)
    f.save(temp_path)

    # Read raw bytes for backend verification
    with open(temp_path, 'rb') as raw_file:
        raw_bytes = raw_file.read()

    # Parse .eml file
    parsed_email = parse_eml(temp_path)

    # Extract URLs and suspicious keywords
    urls = extract_urls(parsed_email['body_text'])
    keywords = find_suspicious_keywords(parsed_email['body_text'])

    # Live SPF/DKIM/DMARC verification
    spf_dkim_dmarc = check_email_auth(raw_bytes.decode(errors='ignore'))

    # Risk classification
    risk_level = classify_risk(spf_dkim_dmarc)

    # URL and attachment risk analysis
    url_analysis = analyze_url_risk(urls, parsed_email['from'])
    attachments_analysis = analyze_attachment_risk(parsed_email['attachments'])

    # Add phishing analysis
    phishing_data = {
        'urls_detected': url_analysis,
        'suspicious_keywords': keywords,
        'spf_dkim_dmarc': spf_dkim_dmarc,
        'risk_level': risk_level,
        'attachments': attachments_analysis
    }
    parsed_email['phishing_analysis'] = phishing_data

    # Save to database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO email_logs (sender, receiver, subject, date, risk_level, data)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        parsed_email['from'],
        parsed_email['to'],
        parsed_email['subject'],
        parsed_email['date'],
        risk_level,
        json.dumps(parsed_email)
    ))
    conn.commit()
    conn.close()

    # Always return JSON for frontend
    return jsonify(parsed_email)

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, sender, receiver, subject, date, risk_level, data FROM email_logs ORDER BY id DESC')
    emails = []
    for row in c.fetchall():
        email_record = {
            'id': row[0],
            'from': row[1],
            'to': row[2],
            'subject': row[3],
            'date': row[4],
            'risk_level': row[5],
            'data': json.loads(row[6])
        }
        emails.append(email_record)
    conn.close()
    return render_template('dashboard.html', emails=emails)

@app.route('/email/<int:email_id>')
def email_details(email_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, sender, receiver, subject, date, risk_level, data FROM email_logs WHERE id=?', (email_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return f"<h2>Email with ID {email_id} not found</h2>", 404

    email_record = {
        'id': row[0],
        'from': row[1],
        'to': row[2],
        'subject': row[3],
        'date': row[4],
        'risk_level': row[5],
        'data': json.loads(row[6])
    }

    return render_template('details.html', email=email_record)

@app.route('/download/<int:email_id>')
def download_email_json(email_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT subject, data FROM email_logs WHERE id=?', (email_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return f"<h2>Email with ID {email_id} not found</h2>", 404

    subject, data = row
    filename = f"email_{email_id}.json"

    response = app.response_class(
        response=data,
        status=200,
        mimetype='application/json',
    )
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route('/analyze')
def analyze_file():
    eml_path = request.args.get('file')
    if not eml_path or not os.path.isfile(eml_path):
        return jsonify({'error': 'File not found'}), 404

    with open(eml_path, 'rb') as raw_file:
        raw_bytes = raw_file.read()

    parsed_email = parse_eml(eml_path)
    urls = extract_urls(parsed_email['body_text'])
    keywords = find_suspicious_keywords(parsed_email['body_text'])

    # Live SPF/DKIM/DMARC
    spf_dkim_dmarc = check_email_auth(raw_bytes.decode(errors='ignore'))
    risk_level = classify_risk(spf_dkim_dmarc)
    url_analysis = analyze_url_risk(urls, parsed_email['from'])
    attachments_analysis = analyze_attachment_risk(parsed_email['attachments'])

    parsed_email['phishing_analysis'] = {
        'urls_detected': url_analysis,
        'suspicious_keywords': keywords,
        'spf_dkim_dmarc': spf_dkim_dmarc,
        'risk_level': risk_level,
        'attachments': attachments_analysis
    }

    return jsonify(parsed_email)

# -------------------------------
# Live SPF/DKIM/DMARC verification via AJAX
# -------------------------------
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "No email content provided"}), 400

    email_raw = data["email"]
    result = check_email_auth(email_raw)
    return jsonify(result)

# -------------------------------
# Run Flask app
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
