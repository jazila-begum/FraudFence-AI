# FraudFence-AI: Smart AI for Safer Conversations
FraudFence is an AI-powered scam detection assistant designed to protect elderly users from phishing and social engineering attacks.

The system analyzes suspicious messages using a **hybrid intelligence approach** that combines:

* **Deterministic rule-based scam detection**
* **Reasoning-based analysis using Gemini Flash 3 Preview**

FraudFence identifies red flags, estimates scam probability, explains the risks in simple language, and provides **safe guidance on how to respond**.

---

# Problem

Elderly users are among the most frequent targets of:

* Phishing scams
* Impersonation fraud
* Lottery scams
* Romance scams
* Investment fraud

These attacks often rely on **psychological pressure, urgency, and deception**, making them difficult to detect without assistance.

FraudFence helps bridge this gap by **automatically analyzing suspicious messages and offering clear, understandable safety advice.**

---

# Key Features

Hybrid AI Detection
Combines rule-based detection with Gemini reasoning for stronger scam analysis.

Scam Probability Scoring
Calculates a risk score between **0–100** indicating the likelihood of fraud.

Red Flag Identification
Highlights suspicious patterns such as urgency, impersonation, suspicious links, or payment requests.

Simple Explanations
Provides explanations written in **easy language suitable for elderly users.**

Safe Response Guidance
Suggests what the user should do next (ignore, verify, report, etc.).

Robust Architecture
Modular, production-ready Python structure with proper error handling.

---

# System Architecture

FraudFence uses a **hybrid intelligence pipeline**:

Message Input
↓
Rule-Based Scam Detection
↓
Gemini Flash 3 Preview Analysis
↓
Score Fusion Engine
↓
Structured Safety Response

The rule engine provides **deterministic detection**, while Gemini provides **contextual reasoning and explanation**.

---

# Project Structure

```
elderly-scam-alert/
│
├── app.py
├── scam_rules.py
├── gemini_engine.py
├── scorer.py
├── utils.py
├── requirements.txt
└── .env
```

---

# Example Output

```json
{
  "red_flags": [
    "urgent language",
    "gift card payment request"
  ],
  "scam_probability": 87,
  "scam_category": "impersonation",
  "explanation": "This message pressures you to act quickly and asks for unusual payment.",
  "safe_response": "Do not reply. Contact your bank directly using official numbers."
}
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/yourusername/fraudfence.git
cd fraudfence
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create `.env`

```
GEMINI_API_KEY=your_api_key_here
```

---

# Running the Project

Run the application:

```bash
python app.py
```

Then enter a suspicious message to analyze.

---

# Technologies Used

Python
Google Gemini Flash 3 Preview
Rule-Based NLP Detection
Hybrid AI Scoring
JSON Structured Output
python-dotenv

---

# Future Improvements

Voice-based scam detection for phone calls
WhatsApp / SMS integration
Real-time scam alert mobile app
Adaptive scam pattern learning
Multilingual support for elderly users

---

# License

This project is licensed under the Apache License 2.0.

