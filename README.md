PhishGuard — Super SOC Email Security Dashboard

PhishGuard is a Python + Flask project that helps SOC analysts detect phishing emails using offline analysis (keyword, URL, attachment checks) and live SPF/DKIM/DMARC verification. The dashboard visualizes email risk levels in real-time and provides detailed inspection of suspicious messages.

🔹 Features

Upload .eml email files for analysis.

Offline analysis:

Suspicious keywords detection

URL risk analysis (shortened links, IP-based domains)

Attachment risk analysis (dangerous file types)

Live verification: SPF, DKIM, DMARC checks

Risk classification:

Safe

Suspicious

High Risk

Interactive dashboard with:

Table of emails

Risk-level pie chart and bar chart

Modal view for email details

Search & filter by sender, subject, or risk

Download individual email JSON reports

Export CSV reports for offline review

🔹 Demo (Optional)

For demo purposes, you can use simulated emails to showcase all three risk levels:

Safe: safe_email@example.com

Suspicious: suspicious_email@example.com

High Risk: high_risk_email@example.com

🔹 Project Structure
phishguard/
│
├── app/
│   ├── analyzer.py          # Email parsing and analysis functions
│   ├── backend.py           # SPF/DKIM/DMARC verification
│   ├── main.py              # Flask application
│   ├── phishguard.db        # SQLite database
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── details.html
│   └── venv/                # Python virtual environment
│
├── samples/                 # Sample .eml test files
├── reports/                 # Generated CSV/JSON reports
├── requirements.txt         # Python dependencies
└── package.json             # Frontend dependencies (if any)

🔹 Installation

Clone the repo:

git clone https://github.com/Loke31033/PhishGuard.git
cd PhishGuard/app


Create virtual environment and activate:

python3 -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows


Install dependencies:

pip install -r requirements.txt

🔹 Run the Project
python main.py


Open your browser at:

http://127.0.0.1:5000/dashboard


Upload .eml files and explore the dashboard.

🔹 How it Works

Upload emails: .eml files are parsed for headers, body, URLs, and attachments.

Offline analysis: Keyword matching, URL heuristics, attachment checks.

Live verification: Check SPF, DKIM, DMARC via backend.py.

Risk classification: Combines all signals to classify emails.

Dashboard & charts: Emails displayed in an interactive table, with charts showing Safe/Suspicious/High Risk counts.

🔹 Dependencies

Python 3.10+

Flask

dnspython

dkimpy

pyspf

SQLite3 (for storing email logs)

Chart.js (for frontend charts)

Install via:

pip install Flask dnspython dkimpy pyspf

🔹 Contributing

Contributions welcome! Feel free to open issues or submit pull requests.

🔹 License

This project is MIT Licensed — see LICENSE file for details.
