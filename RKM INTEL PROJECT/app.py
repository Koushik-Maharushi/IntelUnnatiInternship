import streamlit as st
import pickle
import numpy as np
import re
import ipaddress
import socket
import ssl
from urllib.parse import urlparse

# Load the trained model
with open("XGBoostClassifier.pickle.dat", "rb") as file:
    model = pickle.load(file)

# ---------------- Feature Functions ----------------

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
        r"bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|"
        r"post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
        r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|"
        r"bitly\.com|cur\.lv|q\.gs|po\.st|bc\.vc|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|"
        r"yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com"
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
            with context.wrap_socket(sock, server_hostname=hostname):
                return 1
    except:
        return 0


def domainAge():
    return 1  

def domainEnd():
    return 1  

def webTraffic():
    return 1  

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
        domainAge(),     
        domainEnd(),     
        webTraffic(),    
        dnsRecord(url),
        iFrame(url),
        mouseOver()
    ]


st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️")
st.title("🔍 Phishing URL Detection App")
url = st.text_input("Enter a URL to check")

if st.button("Predict"):
    features = np.array([extract_features(url)])
    if features.shape[1] != 16:
        st.error("❌ Feature count mismatch.")
    else:
        prediction = model.predict(features)[0]
        result = "🔴 Phishing" if prediction == 0 else "🟢 Legitimate"
        st.success(f"Prediction: **{result}**")
