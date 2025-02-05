import requests
from bs4 import BeautifulSoup
import re
import tldextract
import joblib
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

# Load pre-trained machine learning model (to be trained separately)
try:
    model = joblib.load("phishing_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
except FileNotFoundError:
    print("[!] Machine learning model not found. Ensure phishing_model.pkl and vectorizer.pkl exist.")
    exit()

# List of common phishing indicators
suspicious_keywords = ["banking", "update", "verify", "login", "secure", "account", "password", "authentication"]

# Function to check URL legitimacy
def check_url_legitimacy(url):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain
    
    # Check for long subdomains which can be suspicious
    if len(subdomain.split('.')) > 2:
        print("[!] Suspicious long subdomain detected: ", subdomain)
        return False
    
    return True

# Function to analyze website content for phishing indicators
def analyze_website_content(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print("[-] Unable to fetch website content.")
            return False
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text().lower()
        
        for keyword in suspicious_keywords:
            if keyword in text:
                print(f"[!] Potential phishing keyword detected: {keyword}")
                return False
        
        return True
    except requests.exceptions.RequestException as e:
        print("[-] Error accessing the website:", e)
        return False

# Function to predict phishing probability using machine learning
def predict_phishing(url):
    url_features = np.array([url])
    transformed_url = vectorizer.transform(url_features)
    prediction = model.predict(transformed_url)
    probability = model.predict_proba(transformed_url)[:, 1][0] * 100
    
    print(f"[+] Phishing probability: {probability:.2f}%")
    return prediction[0] == 1

# Function to check URL against Google Safe Browsing API
def check_google_safe_browsing(url, api_key):
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    params = {"key": api_key}
    response = requests.post(safe_browsing_url, json=payload, params=params)
    
    if response.status_code == 200 and response.json().get("matches"):
        print("[!] Warning: This website is flagged by Google Safe Browsing!")
        return False
    return True

if __name__ == "__main__":
    url = input("Enter website URL to check: ")
    api_key = "your-google-safe-browsing-api-key"  # Replace with your API key
    
    google_safe = check_google_safe_browsing(url, api_key)
    phishing_risk = predict_phishing(url)
    url_check = check_url_legitimacy(url)
    content_check = analyze_website_content(url)
    
    if google_safe and not phishing_risk and url_check and content_check:
        print("[+] Website appears to be safe.")
    else:
        print("[!] Warning: This website may be a phishing site!")
