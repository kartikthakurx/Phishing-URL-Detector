import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.parse import urlparse, parse_qs
import tldextract
import re, ssl, socket, datetime, math
import validators, requests, whois, bs4
from difflib import SequenceMatcher
import dns.resolver

BRAND_DOMAINS = [
    "paypal.com", "apple.com", "microsoft.com", "facebook.com",
    "bankofamerica.com", "amazon.com", "netflix.com"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "confirm", "account", "phishing", "webscr", "banking"
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}




def is_valid_url(u: str) -> bool:
    try:
        return bool(validators.url(u))
    except Exception:
        return False

def normalize_url(u: str) -> str:
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return re.sub(r'%[0-9a-f]{2}', '', u)


def is_ip_address(host: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None

def get_ssl_cert(hostname: str):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        s.settimeout(3.0)
        s.connect((hostname, 443))
        cert = s.getpeercert()
        s.close()
        return cert
    except Exception:
        return None

def days_until_expiry(cert) -> int:
    if not cert or "notAfter" not in cert:
        return -1
    try:
        expires = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        delta = expires - datetime.datetime.utcnow()
        return max(delta.days, -1)
    except Exception:
        return -1

def shannon_entropy(s: str) -> float:
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def normalized_edit_distance(a: str, b: str) -> float:
    return 1.0 - SequenceMatcher(None, a, b).ratio()

def min_distance_to_brands(domain: str, subdomain: str = "") -> float:
    full = (subdomain + "." + domain).lower()
    return min(normalized_edit_distance(full, b) for b in BRAND_DOMAINS)


def fetch_page_title(url: str) -> str:
    try:
        r = requests.get(url, timeout=5)
        soup = bs4.BeautifulSoup(r.text, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip().lower()
    except Exception:
        pass
    return ""

def check_common_ports(ip: str) -> list:
    ports = [21, 22, 23, 25, 80, 443, 8080]
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
        except:
            continue
    return open_ports



# Feature 

def extract_features(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    if not is_valid_url(url):
        raise ValueError("Malformed URL")
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = parsed.hostname or ""
    reg_domain = f"{ext.domain}.{ext.suffix}"
    
    
    features = {
        "url": url,
        "normalized_url": url,
        "url_length": len(url),
        "hostname": domain,
        "hostname_length": len(domain),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_qm": url.count("?"),
        "num_eq": url.count("="),
        "num_params": len(parse_qs(parsed.query)),
        "has_ip": is_ip_address(domain),
        "has_https": url.startswith("https://"),
        "entropy": shannon_entropy(domain) if domain else 0.0,
        "edit_dist_brand": min_distance_to_brands(reg_domain, ext.subdomain),
        "suspicious_tld": ext.suffix.lower() in SUSPICIOUS_TLDS,
        "contains_keyword": any(k in url for k in SUSPICIOUS_KEYWORDS),
        "ssl_valid": False,
        "ssl_days_left": -1,
        "http_status": -1,
        "redirect_chain": [],
        "title_brand_mismatch": True,
    }

 # WHOIS Information
    try:
        w = whois.whois(reg_domain) or {}
        def first_date(val):
            if isinstance(val, list):
                return val[0] if val else None
            return val
        cd = first_date(w.get("creation_date"))
        ed = first_date(w.get("expiration_date"))
        ud = first_date(w.get("updated_date"))
        

        features.update({
           "domain": reg_domain,
        "whois_creation_date": str(cd) if cd else "Unknown",
        "whois_expiration_date": str(ed) if ed else "Unknown",
        "whois_last_updated": str(ud) if ud else "Unknown",
        "registrar": getattr(w, "registrar", "Unknown"),
        "domain_registered_country": getattr(w, "country", "Unknown")
        })
    except Exception as e:
        print(f"[WHOIS ERROR] {e}")
        features.update({
        "domain": reg_domain,
        "whois_creation_date": "Unknown",
        "whois_expiration_date": "Unknown",
        "whois_last_updated": "Unknown",
        "registrar": "Unknown",
        "domain_registered_country": "Unknown"
    })
     #ssl ertificate check
    cert = get_ssl_cert(domain)
    features["ssl_valid"] = bool(cert)
    features["ssl_days_left"] = days_until_expiry(cert)

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        features["http_status"] = resp.status_code
        features["redirect_chain"] = [h.url for h in resp.history] + [resp.url]

        # Redirect & Behavior Features
        features["redirect_chain_length"] = max(0, len(features["redirect_chain"]) - 1)
        final_host = urlparse(resp.url).hostname or ""
        features["redirects_to_different_domain"] = final_host != domain

        # Basic iframe redirection detection
        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        iframes = soup.find_all("iframe")
        features["iframe_redirection"] = any("src" in iframe.attrs for iframe in iframes)
        
        # Title check
        title = fetch_page_title(url)
        for b in BRAND_DOMAINS:
            token = b.split(".")[0]
            if token in reg_domain:
                features["title_brand_mismatch"] = token not in title
                break
    except Exception:
        features["http_status"] = -1
        features["redirect_chain"] = []
        features["redirect_chain_length"] = 0
        features["final_redirect_is_ip"] = False
        features["redirects_to_different_domain"] = False
        features["iframe_redirection"] = False
    

        #DNS / Hosting info
    try:

        socket.gethostbyname(domain)
        features["dns_record_exists"] = True
    except:

        features["dns_record_exists"] = False


    try:

        mx = dns.resolver.resolve(reg_domain, 'MX')
        features["has_mx_record"] = len(mx) > 0
    except:
        features["has_mx_record"] = False


    try:
        same_ip = socket.gethostbyname_ex(domain)[2]
        features["multiple_domains_same_ip"] = len(same_ip) > 1
    except:
        features["multiple_domains_same_ip"] = False

    try:
        ip_addr = socket.gethostbyname(domain)
        features["common_ports_open"] = check_common_ports(ip_addr)
    except:
        features["common_ports_open"] = False
        
    features["url_contains_unicode"] = any(ord(c) > 127 for c in raw_url)
    features["fake_subdomain_trick"] = any(
    brand.split(".")[0] in ext.subdomain.lower() for brand in BRAND_DOMAINS)
    features["url_has_double_slash_path"] = parsed.path.count("//") > 0
    features["uses_hex_encoding"] = bool(re.search(r"%[0-9a-fA-F]{2}", raw_url))

    features["has_capital_letter"] = any(c.isupper() for c in raw_url)

    return features

def analyze(features: dict):
    score = 0
    reasons = []


    if features["url_length"] > 75:
        score += 1; reasons.append("Long URL")
    if features["hostname_length"] > 30:
        score += 2; reasons.append("Long hostname")
    if features["num_dots"] > 4:
        score += 1; reasons.append("Too many dots")
    if features["num_hyphens"] > 3:
        score += 1; reasons.append("Many hyphens")
    if features["num_at"] > 0:
        score += 7; reasons.append("Contains '@'")
    if features["entropy"] > 5.2:
        score += 1; reasons.append("High hostname entropy")


    if features["edit_dist_brand"] < 0.15:
        score += 3; reasons.append("Very similar to known brand")
    if features["contains_keyword"]:
        score += 2; reasons.append("Suspicious keyword in URL")
    if features["suspicious_tld"]:
        score += 3; reasons.append("Free / suspicious TLD")
    if features["has_ip"]:
        score += 4; reasons.append("Uses IP instead of domain")

    if features.get("has_capital_letter"):
        score += 8
        reasons.append("URL contains capital letters")

    if not features["has_https"]:
        score += 2; reasons.append("No HTTPS")
    if not features["ssl_valid"]:
        score += 3; reasons.append("Invalid SSL")
    elif 0 <= features["ssl_days_left"] < 30:
        score += 1; reasons.append("SSL expires soon")



    if features["http_status"] >= 400 or features["http_status"] < 0:
        score += 2; reasons.append("Bad HTTP status")



    #Verdict
    if score >= 7:
        verdict = "🚨 PHISHING"
    elif score >= 5:
        verdict = "⚠️ Suspicious"
    else:
        verdict = "✅ SAFE"

    return verdict, score, reasons



# GUI


def on_check():
    raw = url_entry.get().strip()
    if not raw:
        messagebox.showwarning("Input Required", "Please enter a URL.")
        return
    try:
        feat = extract_features(raw)
        verdict, score, reasons = analyze(feat)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze URL:\n{e}")
        return


    result_text.tag_configure("centered_blue", justify="center", foreground="blue", font=("Arial", 18, "bold"))

    verdict_colors = {
        "✅ SAFE": "green",
        "⚠ SUSPICIOUS": "black",
        "🚨 PHISHING": "red"
    }
    verdict_color = verdict_colors.get(verdict, "black")
    result_text.tag_configure("verdict_tag", justify="center", foreground=verdict_color, font=("Arial", 20, "bold"))



    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)

    result_text.insert(tk.END, f"URL: {feat['url']}\n", "verdict_tag")

    result_text.insert(tk.END, f"Verdict: {verdict}\n\n", "verdict_tag")


    result_text.insert(tk.END, "\n\n--------- URL Structure & SSL Certificate ---------\n", "centered_blue",)
    for k in [
        "url_length", "hostname_length","path_length","has_ip", "has_https",
        "num_dots","num_hyphens","num_at","num_qm","num_eq","entropy", "edit_dist_brand", 
        "ssl_valid", "ssl_days_left", "http_status"
    ]:
        result_text.insert(tk.END, f" {k}: {feat[k]}\n", "pad_center")


    result_text.insert(tk.END, "\n\n\n--------- WHOIS Information ---------\n", "centered_blue")
    result_text.insert(tk.END, f" • Domain:          {feat['domain']}\n", "pad_center")
    result_text.insert(tk.END, f" • Registered On:   {feat['whois_creation_date']}\n", "pad_center")
    result_text.insert(tk.END, f" • Expires On:      {feat['whois_expiration_date']}\n", "pad_center")
    result_text.insert(tk.END, f" • Updated On:      {feat['whois_last_updated']}\n", "pad_center")
    result_text.insert(tk.END, f" • Registrar:       {feat['registrar']}\n", "pad_center")
    result_text.insert(tk.END, f" • Country:         {feat['domain_registered_country']}\n", "pad_center")

    result_text.insert(tk.END, "\n\n\n--------- Redirects & Behavior ---------\n", "centered_blue")
    result_text.insert(tk.END, f" • Redirect Chain Length:   {feat['redirect_chain_length']} {'(Suspicious)' if feat['redirect_chain_length'] >= 2 else ''}\n", "pad_center")
    result_text.insert(tk.END, f" • Cross-domain Redirect:   {feat['redirects_to_different_domain']}\n", "pad_center")
    result_text.insert(tk.END, f" • Iframe Redirection:      {feat['iframe_redirection']}\n", "pad_center")


    result_text.insert(tk.END, "\n\n\n--------- Redirect Chain ---------\n", "centered_blue")
    for u in feat["redirect_chain"]:
        result_text.insert(tk.END, f" -> {u}\n", "pad_center")

    result_text.insert(tk.END, "\n\n\n--------- DNS and Hosting Info ---------\n", "centered_blue")
    result_text.insert(tk.END, f" • DNS Record Exists:        {feat['dns_record_exists']}\n", "pad_center")
    result_text.insert(tk.END, f" • Has MX Record:            {feat['has_mx_record']}\n", "pad_center")
    result_text.insert(tk.END, f" • Multiple Domains on IP:   {feat['multiple_domains_same_ip']}\n", "pad_center")
    ports = feat['common_ports_open']
    if ports:
        port_labels = {
        21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS",
        8080: "Alt-HTTP"
        }
        formatted = [f"{p} ({port_labels.get(p, 'Unknown')})" for p in ports]
        result_text.insert(tk.END, f" • Open Ports:        {', '.join(formatted)}\n", "pad_center")

    else:
        result_text.insert(tk.END, f" • Open Ports:        None\n", "pad_center")


    result_text.insert(tk.END, "\n\n\n--------- Suspicious Patterns & Tricks ---------\n", "centered_blue")


    val = feat["suspicious_tld"]
    hint = f"(uses .{tldextract.extract(feat['url']).suffix}, a known phishing TLD)" if val else ""
    result_text.insert(tk.END, f" • Suspicious TLD:             {val} {hint}\n", "pad_center")


    val = feat["contains_keyword"]
    kw_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in feat["url"]]
    hint = f"(keywords {', '.join(kw_matches)})" if val else ""
    result_text.insert(tk.END, f" • Contains Keyword:           {val} {hint}\n", "pad_center")

    val = feat.get("fake_subdomain_trick", False)
    hint = f"(e.g. subdomain like {tldextract.extract(feat['url']).subdomain})" if val else ""
    result_text.insert(tk.END, f" • Fake Subdomain Trick:       {val} {hint}\n", "pad_center")


    val = feat.get("url_has_double_slash_path", False)
    hint = f"({urlparse(feat['url']).path})" if val else ""
    result_text.insert(tk.END, f" • Double Slash in Path:       {val} {hint}\n", "pad_center")


    val = feat.get("uses_hex_encoding", False)
    hex_matches = re.findall(r"%[0-9a-fA-F]{2}", feat['url'])
    hint = f"{' '.join(hex_matches)}" if val else ""
    result_text.insert(tk.END, f" • Uses Hex Encoding:          {val} {hint}\n", "pad_center")



    result_text.insert(tk.END, "\n\n\n--------- Reasons ---------\n", "centered_blue") 
    if reasons:
        for r in reasons:
            result_text.insert(tk.END, f" • {r}\n", "pad_center")
    else:
        result_text.insert(tk.END, " • No suspicious features detected.\n", "pad_center")


# Build GUI
root = tk.Tk()
root.configure(bg="#AFAFAF") 
root.title("\ud83d\udd12 Phishing URL Detector")
root.geometry("1000x800")

tk.Label(root, text="PHISHING  URL  DETECTOR", font=("Helvetica", 38, "bold"), bg="#AFAFAF", fg="black").pack(pady=(40, 0))



frm = tk.Frame(root, bg="#000000")
frm.pack(pady=(40, 40), padx=150, fill="x")

tk.Label(root, text="URL INFORMATION", font=("Arial", 24, "bold"), bg="#AFAFAF", fg="black").pack(pady=(10, 20))

frm.columnconfigure(0, weight=0)
frm.columnconfigure(1, weight=1)
frm.columnconfigure(2, weight=0)

tk.Label(frm, text="  Enter URL:", font=("Arial", 18,"bold"), bg="#000000", fg="white").grid(row=0, column=0, sticky="w", padx=5)
url_entry = tk.Entry(frm, font=("Arial", 20,"bold"), bg="#FFFFFF", fg="blue", insertbackground="white")
url_entry.grid(row=0, column=1, sticky="ew", padx=5)

check_btn = tk.Button(frm, text=" CHECK ", command=on_check,
                      bg="#70fa73", fg="white", font=("Arial", 22, "bold"),
                      width=10) 
check_btn.grid(row=0, column=2, padx=(5, 0)) 

result_text = scrolledtext.ScrolledText(root, font=("Consolas", 18,"bold"), state="disabled", bg="#FFFFFF", fg="black", insertbackground="white")
result_text.pack(fill="both", expand=True, padx=150, pady=(0, 50))

result_text.tag_configure("pad_center", justify="center", spacing3=4)

root.mainloop()
