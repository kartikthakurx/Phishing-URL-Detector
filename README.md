# 🔒 Phishing URL Detector
Phishing URL Detector is a desktop GUI application built with Python and Tkinter that inspects URLs across structure, SSL certificates, WHOIS records, DNS and hosting details, redirects, and suspicious URL patterns to classify them as Safe, Suspicious, or Phishing.

## ✨ Features

- **Desktop GUI Scanner:** Enter any URL and view formatted scan results (`SAFE`, `Suspicious`, or `PHISHING`)
- **URL Structure & Heuristic Checks:** Inspects URL, hostname, path, and query lengths, dots, hyphens, `@` symbols, query parameters, IP addresses, HTTPS usage, Shannon entropy, brand similarity distance, suspicious TLDs, and keywords
- **SSL Certificate Check:** Checks whether an SSL certificate is valid and calculates remaining days until expiry
- **WHOIS, DNS & Hosting Info:** Fetches domain creation, expiration, and update dates, registrar, country, DNS/MX record status, multiple domains on the same IP, and open common ports
- **Redirect & Pattern Detection:** Tracks redirect chains, cross-domain redirects, `<iframe>` elements, fake subdomain tricks, double slashes in paths, and hex or Unicode encoding

## 🛠️ Tech Stack

- **GUI & Language:** Python, Tkinter (`messagebox`, `scrolledtext`)
- **Libraries Used:** `requests`, `urllib.parse`, `tldextract`, `validators`, `whois`, `dnspython` (`dns.resolver`), `beautifulsoup4` (`bs4`), `ssl`, `socket`, `re`, `math`, `difflib`


## 🚀 Local Installation & Setup

### Prerequisites
- Python 3.x
- Git CLI

### Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/kartikthakurx/Phishing-URL-Detector.git
   cd phishing-url-detector

2. **Install dependencies:**

pip install requests tldextract validators python-whois beautifulsoup4 dnspython

3. **Run the application:**

python phishingurl.py

Note: Live WHOIS, DNS, SSL, and HTTP checks require an active internet connection and may time out or vary depending on target servers and WHOIS rate limits.

###👨‍💻 Developer
Kartik Thakur 
GitHub: @kartikthakurx

### 📜 License
Licensed under the MIT License.
