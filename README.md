# URL Threat Predictor API 🔐

This is a lightweight FastAPI application designed to predict the threat level of URLs in real time using two machine learning models. It is intended to work as a backend for a browser extension that blocks phishing, malicious, and dangerous websites.

---

## 🚀 Features
- Uses two pre-trained ML models for prediction
- Logic-based final classification:
  - benign + benign → benign
  - benign + phishing → phishing
  - malicious + benign → malicious
  - malicious + phishing → dangerous
- Integrates easily with browser extensions
- Built with FastAPI and deployed via Render.com

---

## 📁 File Structure

├── app.py # Main FastAPI backend
├── requirements.txt # Python dependencies
├── model1.pkl # First trained model
├── model2.pkl # Second trained model


---

## 📡 API Endpoint

| Method | Endpoint    | Description             |
|--------|-------------|-------------------------|
| POST   | /predict    | Takes a URL and returns its threat level |

### Example Request:
```json
{
  "url": "http://example.com"
}

**### Example Response:**

{
  "result": "malicious"
}

