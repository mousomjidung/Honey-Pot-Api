# 🍯 Agentic Honey-Pot for Scam Detection (Abhishek)

> Agentic Honey-Pot for Scam Detection & Intelligence Extraction

An autonomous, AI-driven backend that identifies scam attempts, engages scammers in realistic multi-turn conversations, and extracts actionable intelligence (UPI IDs, bank accounts, phishing links) without revealing its identity.

## 🚀 Features

* **🕵️‍♂️ Scam Detection:** Uses regex-based intelligence extraction to identify suspicious keywords ("KYC", "Block", "OTP"), phishing links, and financial patterns.
* **🤖 Agent Persona ("Abhishek"):** A 64-year-old Indian uncle persona who is confused and scared, designed to stall scammers and elicit more information.
* **🧠 Generative AI:** Powered by **Google Gemini 2.5/2.0 Flash** models for context-aware, human-like responses.
* **⚡ High Performance:** Built on **FastAPI** with asynchronous request handling and `BackgroundTasks` for non-blocking callbacks.
* **🔄 Session Management:** Implements an LRU (Least Recently Used) cache to manage active conversations efficiently under load.
* **📡 Webhook Integration:** Automatically reports extracted intelligence to the central evaluation server.

## 🛠️ Tech Stack

* **Framework:** Python 3.10+ & FastAPI
* **AI Model:** Google GenAI SDK (Gemini 2.5 Flash / 1.5 Pro)
* **Validation:** Pydantic V2 & Pydantic Settings
* **Server:** Uvicorn (ASGI)
* **HTTP Client:** HTTPX (Async)

## 📂 Project Structure

```bash
.
├── main.py                # Main application entry point (FastAPI)
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (API Keys)
└── README.md              # Project documentation

```

## ⚙️ Installation & Setup

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/agentic-honeypot.git
cd agentic-honeypot

```


2. **Create a Virtual Environment**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

```


3. **Install Dependencies**
```bash
pip install fastapi uvicorn httpx python-dotenv google-genai pydantic pydantic-settings

```


4. **Configure Environment Variables**
Create a `.env` file in the root directory:
```ini
GEMINI_API_KEY=your_google_gemini_api_key
REQUIRED_API_KEY=
CALLBACK_URL=
# Optional Tuning
MAX_SESSIONS=500
CALLBACK_ONLY_ON_SCAM=True

```


5. **Run the Server**
```bash
python main.py
# OR
uvicorn main:app --reload --port 10000

```



## 🔌 API Usage

**Base URL:** `http://localhost:10000`

### 1. Analyze Message (Core Endpoint)

**Endpoint:** `POST /analyze`
**Headers:**

* `x-api-key`: `zero-day-101`
* `Content-Type`: `application/json`

**Request Body:**

```json
{
  "sessionId": "session-001",
  "message": {
    "sender": "scammer",
    "text": "Your SBI account is blocked. Click http://fake-bank.com to verify KYC.",
    "timestamp": 1770005528731
  },
  "conversationHistory": []
}

```

**Response:**

```json
{
  "status": "success",
  "reply": "Oh my god! My pension comes in that account. What do I do beta?"
}

```

## 📊 How It Works

1. **Ingestion:** The system receives a message via the `/analyze` endpoint.
2. **Extraction:** The `IntelExtractor` scans the text for:
* **Financials:** UPI IDs, Bank Account Numbers.
* **Contact:** Phone numbers, Email addresses.
* **Threats:** Phishing URLs, Keywords (e.g., "arrest", "suspend").


3. **Decision:**
* If scam intent is detected, the **Abhishek Persona** (Gemini AI) takes over.
* If the AI service is unavailable, a **Smart Fallback** rule-based system responds.


4. **Reporting:** Once a scam is confirmed or engagement occurs, a background task sends the intelligence payload to the hackathon evaluation server.

## 🛡️ Security

* **API Key Protection:** All requests must include the `x-api-key` header.
* **Input Sanitization:** Prevents massive payloads from crashing the server.
* **Safe AI:** Configured with Google Safety Settings (HarmBlockThreshold) to prevent the bot from generating toxic content.

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
