# Phishing Website Detector

## 📌 Overview
This tool analyzes website URLs and content to detect potential **phishing websites** using:
- **Machine Learning** to predict phishing probability
- **Google Safe Browsing API** for real-time blacklist checking
- **Keyword-based analysis** to detect suspicious content

## 🚀 Features
✔ **Machine learning-based phishing detection**
✔ **Google Safe Browsing API verification**
✔ **URL analysis for suspicious structures**
✔ **Website content analysis for phishing keywords**
✔ **Real-time risk assessment**

## 📦 Installation
### **1️⃣ Install Dependencies**
```bash
pip install requests beautifulsoup4 tldextract joblib numpy scikit-learn
```

### **2️⃣ Set Up Google Safe Browsing API**
- Get an API key from [Google Developers](https://developers.google.com/safe-browsing/v4/get-started).
- Replace `your-google-safe-browsing-api-key` in the script.

### **3️⃣ Train the Machine Learning Model** (if not available)
```python
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# Sample data (phishing vs real URLs)
urls = ["securebank.com", "verify-login-update.com", "myaccount.paypal-secure.com", "google.com"]
labels = [0, 1, 1, 0]  # 0 = Safe, 1 = Phishing

vectorizer = CountVectorizer()
X = vectorizer.fit_transform(urls)
model = RandomForestClassifier()
model.fit(X, labels)

joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
```

## 🛠 Usage
### **Run the script**
```bash
python phishing_detector.py
```

### **Provide Input**
1. Enter the **URL to check**
2. The script will analyze and display phishing risk

### **Example Output**
```
Enter website URL to check: suspicious-login.com
[+] Phishing probability: 89.5%
[!] Warning: This website may be a phishing site!
```

## ⚠️ Disclaimer
This tool is for **educational and security research purposes only**. **Unauthorized use is illegal**. Ensure you have **explicit permission** before using it.

🔒 **Stay secure!**

