import streamlit as st
import pickle
import numpy as np
import re
import ipaddress
import socket
import ssl
import whois
from urllib.parse import urlparse
from datetime import datetime


with open("XGBoostClassifier.pickle.dat", "rb") as file:
    model = pickle.load(file)



def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    return sum(1 for p in urlparse(url).path.split('/') if len(p) > 0)

def redirection(url):
    return 1 if url.rfind('//') > 6 else 0

def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

def tinyURL(url):
    pattern = re.compile(
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
    )
    return 1 if pattern.search(url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def subDomain(url):
    return 1 if urlparse(url).netloc.count('.') > 2 else 0

def sslFinalState(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return 1
    except:
        return 0

def domainAge(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return 0 if age < 180 else 1
        return 0
    except:
        return 0

def domainEnd(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date:
            days_left = (expiration_date - datetime.now()).days
            return 0 if days_left < 180 else 1
        return 0
    except:
        return 0

def dnsRecord(url):
    try:
        socket.gethostbyname(urlparse(url).netloc)
        return 1
    except:
        return 0

def iFrame(url):
    return 0  

def mouseOver():
    return 1  



def extract_features(url):
    return [
        havingIP(url),
        haveAtSign(url),
        getLength(url),
        getDepth(url),
        redirection(url),
        httpDomain(url),
        tinyURL(url),
        prefixSuffix(url),
        subDomain(url),
        sslFinalState(url),
        domainAge(url),
        domainEnd(url),
        1, 
        dnsRecord(url),
        iFrame(url),
        mouseOver()
    ]



st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️")
st.title("🔍 Phishing URL Detection with XGBoost")
url = st.text_input("🔗 Enter a URL")

if st.button("🚀 Predict"):
    features = np.array([extract_features(url)])
    if features.shape[1] != 16:
        st.error(f"Expected 16 features, got {features.shape[1]}")
    else:
        prediction = model.predict(features)[0]
        result = "🟢 Legitimate" if prediction == 1 else "🔴 Phishing"
        st.success(f"### Prediction: **{result}**")
