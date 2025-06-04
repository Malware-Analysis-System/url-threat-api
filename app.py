import os
import gdown

# Google Drive file IDs
PHISHING_MODEL_ID = "1QqySKm5-D0LlcO6n0VguyNz0LaKr3dts"
MALWARE_MODEL_ID = "1JLXHm8Z_-Rw8ONITaMhViSCvdhhzWRaV"

PHISHING_MODEL_PATH = "phishing_stack.pkl"
MALWARE_MODEL_PATH = "new_malware_stack.pkl"

def download_model(file_id, output_path):
    if not os.path.exists(output_path):
        print(f"Downloading {output_path} from Google Drive...")
        url = f"https://drive.google.com/uc?id={file_id}"
        gdown.download(url, output_path, quiet=False)
    else:
        print(f"{output_path} already exists. Skipping download.")

download_model(PHISHING_MODEL_ID, PHISHING_MODEL_PATH)
download_model(MALWARE_MODEL_ID, MALWARE_MODEL_PATH)

# ---------------------------------------
# Rest of your original app.py code starts here
# ---------------------------------------

from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime

# -------------------------------
# Load Trained Models
# -------------------------------
phishing_model = joblib.load("phishing_stack.pkl")
malware_model = joblib.load("new_malware_stack.pkl")

# -------------------------------
# FastAPI App Init
# -------------------------------
app = FastAPI()

class URLInput(BaseModel):
    url: str

# -------------------------------
# Feature Extraction and Preparation (Copied from Gradio app)
# -------------------------------
def extract_phishing_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""
    tld = hostname.split('.')[-1] if '.' in hostname else ""
    path = parsed.path.lower()
    query = parsed.query.lower()

    phishing_keywords = [
        "login", "signin", "verify", "account", "update", "security",
        "banking", "paypal", "ebay", "amazon", "apple", "microsoft",
        "confirm", "validate", "password", "creditcard", "ssn", "phishing"
    ]

    suspicious_tlds = [
        "xyz", "top", "icu", "ga", "tk", "cf", "ml", "gq", "cc", "pw",
        "club", "info", "stream", "download", "work", "online"
    ]

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_digits": sum(char.isdigit() for char in url),
        "num_special_chars": len(re.findall(r"[^\w\s./]", url)),
        "has_ip_address": 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_suspicious_words": 1 if any(word in url.lower() for word in phishing_keywords) else 0,
        "is_shortened": 1 if any(short in url for short in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "shorte.st"]) else 0,
        "suspicious_tld": 1 if tld in suspicious_tlds else 0,
        "path_keyword_count": sum(1 for word in phishing_keywords if word in path),
        "query_keyword_count": sum(1 for word in phishing_keywords if word in query),
        "tld": tld
    }

def extract_malware_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme
    path = parsed.path.lower()

    malware_keywords = [
        "download", "install", "free", "crack", "keygen", "serial", "torrent",
        "nulled", "patch", "loader", "activator", "setup", "executable", "malware",
        "virus", "trojan", "spyware", "ransomware", "adware", "botnet"
    ]

    url_length = len(url)
    hostname_length = len(hostname)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_digits = len(re.findall(r'\d', url))
    num_specials = len(re.findall(r"[^\w\s./]", url))
    has_suspicious_keyword = any(k in url.lower() for k in malware_keywords)
    has_ip = bool(re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url))
    is_https = scheme == 'https'
    is_shortened = any(s in url for s in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'shorte.st'])
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    path_keyword_count = sum(1 for word in malware_keywords if word in path)

    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        ip_address = None

    try:
        w = whois.whois(url)
        domain_age = (datetime.now() - w.creation_date[0]).days if w.creation_date else -1
        domain_expiry = (w.expiration_date[0] - datetime.now()).days if w.expiration_date else -1
    except:
        domain_age = domain_expiry = -1

    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ttl = answers.rrset.ttl
    except:
        ttl = -1

    ssl_issuer = "Unknown"
    ssl_valid = False
    if is_https and hostname:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                ssl_issuer = issuer if issuer else "Unknown"
                ssl_valid = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') > datetime.now()
        except:
            pass

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_special_chars": num_specials,
        "has_suspicious_keyword": int(has_suspicious_keyword),
        "path_keyword_count": path_keyword_count,
        "has_ip_address": int(has_ip),
        "is_https": int(is_https),
        "is_shortened": int(is_shortened),
        "tld": tld,
        "domain_age_days": domain_age,
        "domain_expiry_days": domain_expiry,
        "dns_ttl": ttl,
        "ssl_issuer": ssl_issuer,
        "ssl_valid": int(ssl_valid)
    }

def prepare_phishing_input(url):
    features = extract_phishing_features(url)
    df = pd.DataFrame([features])
    df = pd.get_dummies(df, columns=["tld"], prefix="tld")
    df = df.reindex(columns=phishing_model.feature_names_in_, fill_value=0)
    return df

def prepare_malware_input(url):
    features = extract_malware_features(url)
    df = pd.DataFrame([features])
    df = pd.get_dummies(df, columns=["tld", "ssl_issuer"], prefix=["tld", "ssl_issuer"])
    df = df.reindex(columns=malware_model.feature_names_in_, fill_value=0)
    return df

# -------------------------------
# Truth Table Logic
# -------------------------------
def final_prediction(phishing_pred, malware_pred):
    if phishing_pred in ["phishing", "malicious"] and malware_pred in ["phishing", "malicious"]:
        return "dangerous"
    elif phishing_pred in ["phishing", "malicious"] and malware_pred == "benign":
        return phishing_pred
    elif phishing_pred == "benign" and malware_pred in ["phishing", "malicious"]:
        return malware_pred
    elif phishing_pred == "benign" and malware_pred == "benign":
        return "benign"
    else:
        return "unknown"

# -------------------------------
# FastAPI Endpoint
# -------------------------------
@app.post("/predict")
def predict_url(data: URLInput):
    try:
        url = data.url

        # Whitelist trusted domains
        trusted_domains = [
                "google.com", "www.google.com",
                "youtube.com", "www.youtube.com",
                "gmail.com", "www.gmail.com",
                "chat.openai.com", "www.chat.openai.com",
                "openai.com", "www.openai.com",
                "chatgpt.com", "www.chatgpt.com",
                "microsoft.com", "www.microsoft.com",
                "apple.com", "www.apple.com",
                "icloud.com", "www.icloud.com",
                "facebook.com", "www.facebook.com",
                "whatsapp.com", "www.whatsapp.com",
                "linkedin.com", "www.linkedin.com",
                "amazon.com", "www.amazon.com",
                "aws.amazon.com", "www.aws.amazon.com",
                "github.com", "www.github.com",
                "openai.com", "www.openai.com",
                "protonmail.com", "www.protonmail.com",
                "cloudflare.com", "www.cloudflare.com",
                "duckduckgo.com", "www.duckduckgo.com",
                "wikipedia.org", "www.wikipedia.org",
                "stackoverflow.com", "www.stackoverflow.com",
                "signal.org", "www.signal.org"
            ]
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or ""
        if domain.lower() in trusted_domains:
            return {
                "url": url,
                "model1_prediction": "benign",
                "model2_prediction": "benign",
                "final_result": "benign"
            }

        phishing_df = prepare_phishing_input(url)
        malware_df = prepare_malware_input(url)

        phishing_result = phishing_model.predict(phishing_df)[0].lower()
        malware_result = malware_model.predict(malware_df)[0].lower()

        final_result = final_prediction(phishing_result, malware_result)

        return {
            "url": url,
            "model1_prediction": phishing_result,
            "model2_prediction": malware_result,
            "final_result": final_result
        }
    except Exception as e:
        return {"error": str(e)}
