# 🛡️ CyberShield – Threat Analysis Dashboard

CyberShield is a full-stack cybersecurity tool that analyzes IP addresses, URLs, and network logs to detect malicious or suspicious activity using real-world threat intelligence APIs.

---

## 🚀 Features

### 🔍 IP Analysis

* Analyze any IPv4/IPv6 address
* Uses AbuseIPDB + VirusTotal
* Unified threat scoring system

### 🌐 URL Scanning

* Extracts IP from URL
* Detects invalid/suspicious domains
* Basic phishing detection

### 📂 Log File Scanner

* Upload `.log` files
* Extracts IPs automatically
* Batch threat analysis

### 📡 Live Network Capture

* Captures real-time packets
* Analyzes detected IPs
* (Works locally only)

### 📊 Dashboard

* Visual threat scores
* Charts and analytics
* Basic & Advanced views

### 🔐 Authentication

* Supabase-based login system
* Scan history tracking

---

## 🏗️ Tech Stack

### Frontend

* Next.js
* React
* CSS Modules

### Backend

* FastAPI
* Python

### APIs Used

* AbuseIPDB
* VirusTotal

### Database & Auth

* Supabase

---

## 📁 Project Structure

```bash
cyber/
├── backend/
│   ├── api.py
│   ├── analyser.py
│   ├── loganalyser.py
│   └── ...
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   └── ...
```

---

## ⚙️ Setup Instructions

### 1. Clone the repo

```bash
git clone https://github.com/your-username/cyber-shield.git
cd cyber-shield
```

---

### 2. Backend Setup

```bash
cd backend
python -m venv env
env\Scripts\activate   # Windows
pip install -r requirements.txt
```

Create `.env`:

```env
SUPABASE_URL=your_url
SUPABASE_KEY=your_key
ABUSE_API_KEY=your_key
VT_API_KEY=your_key
```

Run backend:

```bash
uvicorn api:app --reload
```

---

### 3. Frontend Setup

```bash
cd frontend
npm install
```

Create `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
```

Run frontend:

```bash
npm run dev
```

---

## 🌍 Deployment

* Frontend → Vercel
* Backend → Render
* Database → Supabase

---

## ⚠️ Notes

* Live packet capture requires admin privileges
* Not supported on cloud deployment
* API keys must be kept secure

---

## 🎯 Future Improvements

* Advanced phishing detection
* Domain reputation APIs
* Geo-location visualization
* Improved UI/UX

---

## 👨‍💻 Author

**Smaran Bhoopalam**

---

## ⭐ If you like this project

Give it a star ⭐ on GitHub!
