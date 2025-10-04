import email
from email import policy
import json
import re
from urllib.parse import urlparse

# -------------------------------
# Email parsing
# -------------------------------
def parse_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    parsed = {
        'from': msg.get('From'),
        'to': msg.get('To'),
        'subject': msg.get('Subject'),
        'date': msg.get('Date'),
        'headers': dict(msg.items()),
        'body_text': '',
        'body_html': '',
        'attachments': []
    }

    # Extract body and attachments
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()

            if disp == 'attachment':
                parsed['attachments'].append({
                    'filename': part.get_filename(),
                    'content_type': ctype
                })
            elif ctype == 'text/plain' and not parsed['body_text']:
                parsed['body_text'] = part.get_content() or ''
            elif ctype == 'text/html' and not parsed['body_html']:
                parsed['body_html'] = part.get_content() or ''
    else:
        ctype = msg.get_content_type()
        if ctype == 'text/plain':
            parsed['body_text'] = msg.get_content() or ''
        elif ctype == 'text/html':
            parsed['body_html'] = msg.get_content() or ''

    return parsed

# -------------------------------
# Phishing detection helpers
# -------------------------------
def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text or '')

def find_suspicious_keywords(text):
    keywords = ['verify', 'urgent', 'immediately', 'suspend', 'failure', 'account', 'click here']
    return [word for word in keywords if word.lower() in (text or '').lower()]

# -------------------------------
# URL Risk Analysis
# -------------------------------
def analyze_url_risk(urls, from_email):
    url_risks = []
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc']

    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        risk = "Safe"

        if any(short in hostname for short in shortened_domains):
            risk = "Suspicious"
        elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
            risk = "Suspicious"
        elif from_domain and from_domain not in hostname:
            risk = "Suspicious"

        url_risks.append({'url': url, 'risk': risk})
    return url_risks

# -------------------------------
# Attachment Risk Analysis
# -------------------------------
def analyze_attachment_risk(attachments):
    risky_extensions = ['.exe', '.js', '.docm', '.bat', '.scr', '.vbs', '.ps1']
    for att in attachments:
        filename = att.get('filename', '').lower()
        att['risk'] = "Suspicious" if any(filename.endswith(ext) for ext in risky_extensions) else "Safe"
    return attachments

# -------------------------------
# SPF + DKIM + DMARC verification
# -------------------------------
def check_spf_dkim_dmarc(headers, raw_message_bytes):
    spf_result = "none"
    dkim_result = "none"
    dmarc_result = "none"

    try:
        auth_results = headers.get("Authentication-Results", "")
        received_spf = headers.get("Received-SPF", "")

        if "spf=pass" in auth_results.lower() or "pass" in received_spf.lower():
            spf_result = "pass"
        elif "spf=fail" in auth_results.lower() or "fail" in received_spf.lower():
            spf_result = "fail"

        if "dkim=pass" in auth_results.lower():
            dkim_result = "pass"
        elif "dkim=fail" in auth_results.lower():
            dkim_result = "fail"
        else:
            try:
                import dkim
                if b"dkim-signature" in raw_message_bytes.lower():
                    dkim_result = "pass" if dkim.verify(raw_message_bytes) else "fail"
            except ImportError:
                pass

        if "dmarc=pass" in auth_results.lower():
            dmarc_result = "pass"
        elif "dmarc=fail" in auth_results.lower():
            dmarc_result = "fail"

    except Exception:
        pass

    return {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result}

# -------------------------------
# Risk classification
# -------------------------------
def classify_risk(spf_dkim_dmarc):
    spf = spf_dkim_dmarc.get("spf", "none")
    dkim = spf_dkim_dmarc.get("dkim", "none")
    dmarc = spf_dkim_dmarc.get("dmarc", "none")

    results = [spf, dkim, dmarc]

    if all(r == "pass" for r in results):
        return "Safe"
    elif any(r == "fail" for r in results):
        return "Suspicious" if results.count("fail") == 1 else "High Risk"
    else:
        return "Unknown"

# -------------------------------
# CLI test
# -------------------------------
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python analyzer.py <path-to-eml>')
        sys.exit(1)

    eml_file = sys.argv[1]
    with open(eml_file, 'rb') as f:
        raw_bytes = f.read()

    parsed_email = parse_eml(eml_file)
    urls = extract_urls(parsed_email['body_text'])
    keywords = find_suspicious_keywords(parsed_email['body_text'])
    url_risks = analyze_url_risk(urls, parsed_email['from'])
    attachments = analyze_attachment_risk(parsed_email['attachments'])
    spf_dkim_dmarc = check_spf_dkim_dmarc(parsed_email['headers'], raw_bytes)
    risk_level = classify_risk(spf_dkim_dmarc)

    parsed_email['phishing_analysis'] = {
        'urls_detected': url_risks,
        'suspicious_keywords': keywords,
        'attachments': attachments,
        'spf_dkim_dmarc': spf_dkim_dmarc,
        'risk_level': risk_level
    }

    print(json.dumps(parsed_email, indent=2))

