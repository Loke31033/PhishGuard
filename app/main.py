from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import os
import email
from email import policy
from email.parser import BytesParser
import json
import re

app = Flask(__name__, template_folder='templates')
CORS(app)

# Get the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, 'templates')
print(f"📁 Current directory: {current_dir}")
print(f"📁 Templates directory: {templates_dir}")

# Import backend function
try:
    from backend import check_email_auth
    print("✅ Backend module loaded successfully")
except ImportError as e:
    print(f"❌ Backend import error: {e}")
    # Fallback function if import fails
    def check_email_auth(email_input):
        return {"error": "Backend module not available"}

def check_file_exists(filename, directory):
    """Check if file exists in specified directory"""
    file_path = os.path.join(directory, filename)
    exists = os.path.exists(file_path)
    print(f"📄 Checking {filename} in {directory}: {'✅ EXISTS' if exists else '❌ MISSING'}")
    return exists

def parse_email_headers(raw_bytes):
    """Parse email headers to extract From domain and other info"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        
        # Extract From header and get domain
        from_header = msg.get('From', '')
        to_header = msg.get('To', '')
        date_header = msg.get('Date', '')
        subject_header = msg.get('Subject', '')
        
        email_address = extract_email_from_header(from_header)
        to_address = extract_email_from_header(to_header)
        domain = email_address.split('@')[-1] if '@' in email_address else None
        
        return {
            'from_email': email_address,
            'to_email': to_address,
            'from_domain': domain,
            'subject': subject_header,
            'date': date_header,
            'all_headers': dict(msg.items())
        }
    except Exception as e:
        return {'error': f'Failed to parse email: {str(e)}'}

def extract_email_from_header(header_value):
    """Extract email address from header"""
    if not header_value:
        return "Unknown"
    
    # Match email pattern in angle brackets or standalone
    email_match = re.search(r'<([^>]+)>', header_value)
    if email_match:
        return email_match.group(1)
    
    # If no angle brackets, try to find email pattern
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    return email_match.group(0) if email_match else header_value

def extract_urls_from_text(text):
    """Extract URLs from email body"""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    return urls

def extract_attachments_from_email(msg):
    """Extract attachment information from email"""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                    })
    return attachments

def format_auth_results_for_dashboard(auth_result):
    """Convert backend auth results to dashboard format"""
    # Extract SPF, DKIM, DMARC status - return ONLY pass/fail strings
    spf_status = "pass" if auth_result.get('spf', {}).get('exists') else "fail"
    dkim_status = "pass" if auth_result.get('dkim', {}).get('exists') else "fail"
    dmarc_status = "pass" if auth_result.get('dmarc', {}).get('exists') else "fail"
    
    # Return ONLY what frontend expects - simple pass/fail strings
    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status
    }

# Root route - serve dashboard from templates folder
@app.route("/")
def home():
    print("🌐 Serving root route / from templates folder")
    if check_file_exists('dashboard.html', templates_dir):
        return render_template('dashboard.html')
    else:
        return jsonify({
            "error": "dashboard.html not found in templates folder",
            "current_directory": current_dir,
            "templates_directory": templates_dir,
            "files_in_templates": os.listdir(templates_dir) if os.path.exists(templates_dir) else "templates folder doesn't exist"
        })

# Dashboard route - explicit
@app.route("/dashboard")
def dashboard():
    print("🌐 Serving /dashboard route from templates folder")
    if check_file_exists('dashboard.html', templates_dir):
        return render_template('dashboard.html')
    else:
        return "Dashboard HTML file not found in templates folder."

# Upload endpoint - FIXED to match frontend expectations
@app.route("/upload", methods=["POST", "GET"])
def upload():
    print("📧 Upload endpoint called")
    if request.method == "GET":
        return jsonify({
            "message": "Use POST to upload email files",
            "example": "curl -X POST -F 'email=@test.eml' http://localhost:5000/upload"
        })
    
    if "email" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["email"]
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    raw_bytes = file.read()
    
    try:
        # Parse email headers
        headers_info = parse_email_headers(raw_bytes)
        
        if 'error' in headers_info:
            return jsonify({"error": headers_info['error']}), 400
        
        domain = headers_info.get('from_domain')
        from_email = headers_info.get('from_email')
        to_email = headers_info.get('to_email', 'Unknown')
        
        if not domain:
            return jsonify({"error": "Could not extract domain from email"}), 400
        
        # Perform authentication check
        auth_result = check_email_auth(from_email)
        
        # Format results for dashboard - ONLY pass/fail strings
        formatted_auth = format_auth_results_for_dashboard(auth_result)
        
        # Parse email again for body and attachments
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        
        # Extract body text for snippet
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            body_text = msg.get_payload(decode=True).decode(errors='ignore')
        
        # Create snippet (first 100 chars)
        snippet = body_text[:100] + "..." if len(body_text) > 100 else body_text
        
        # Extract URLs from body
        urls_detected = extract_urls_from_text(body_text)
        
        # Extract attachments
        attachments = extract_attachments_from_email(msg)
        
        # Format date
        date_header = headers_info.get('date', 'Unknown')
        
        # Return data in EXACT format expected by dashboard.html
        # Frontend will calculate risk_level itself using classifyRisk() function
        return jsonify({
            "from": from_email,
            "to": to_email,
            "headers": {
                "Subject": headers_info.get('subject', 'No Subject'),
                "Date": date_header
            },
            "body_text": body_text,
            "snippet": snippet,
            "spf_dkim_dmarc": formatted_auth,  # Only contains spf, dkim, dmarc as pass/fail strings
            "urls_detected": urls_detected,
            "attachments": [att['filename'] for att in attachments] if attachments else []
            # REMOVED: risk_level and risk_score - frontend calculates these
        })
        
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

# Health check endpoint
@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "Email Auth Checker"})

# Test endpoint
@app.route("/test")
def test():
    return jsonify({
        "message": "Server is working!",
        "current_directory": current_dir,
        "templates_directory": templates_dir,
        "files_in_templates": os.listdir(templates_dir) if os.path.exists(templates_dir) else "templates folder doesn't exist"
    })

# Serve static files
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(current_dir, filename)

if __name__ == "__main__":
    print("🚀 Starting PhishGuard SOC Dashboard...")
    print("📍 Available endpoints:")
    print("   http://localhost:5000/ - Dashboard")
    print("   http://localhost:5000/dashboard - Dashboard (alternative)")
    print("   http://localhost:5000/health - Health Check")
    print("   http://localhost:5000/upload - Upload Email")
    print("   http://localhost:5000/test - Test endpoint")
    
    # Check if dashboard.html exists in templates folder
    if check_file_exists('dashboard.html', templates_dir):
        print("✅ dashboard.html found in templates folder - server should work!")
    else:
        print("❌ dashboard.html NOT FOUND in templates folder")
        if os.path.exists(templates_dir):
            print(f"📁 Files in templates folder: {os.listdir(templates_dir)}")
        else:
            print("❌ templates folder doesn't exist!")
    
    app.run(host="0.0.0.0", port=5000, debug=True)
