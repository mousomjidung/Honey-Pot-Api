import os
import re
import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, Request
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# --- GOOGLE GENAI SDK ---
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None

load_dotenv()

# --- CONFIGURATION ---
class Settings(BaseSettings):
    gemini_api_key: Optional[str] = Field(None, alias="GEMINI_API_KEY")
    required_api_key: str = "zero-day-101"
    callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UltraHoneyPot")

# --- DATA MODELS ---
class MessageDetail(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = Field(default_factory=lambda: int(time.time() * 1000))

class MessageBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sessionId: str
    message: MessageDetail
    conversationHistory: List[Dict[str, Any]] = []

class SessionData(BaseModel):
    scam: bool = False
    count: int = 0
    intel: Dict[str, List[str]] = {
        "bankAccounts": [], "upiIds": [], "phishingLinks": [], 
        "phoneNumbers": [], "suspiciousKeywords": []
    }

# Global In-Memory Store
sessions: Dict[str, SessionData] = {}

# --- ADVANCED EXTRACTION ENGINE ---
class IntelligenceEngine:
    @staticmethod
    def extract(text: str) -> Dict[str, List[str]]:
        low_text = text.lower()
        # Clean digits for stubborn scammers hiding numbers with spaces
        clean_num = re.sub(r'[^\d]', '', text)
        
        # 1. Bank Accounts (9-18 digits)
        banks = re.findall(r'\b\d{9,18}\b', text) + re.findall(r'\d{9,18}', clean_num)
        
        # 2. UPI IDs (Improved Pattern)
        upi = re.findall(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}', text)
        
        # 3. Phishing Links (Handles bit.ly, tinyurl, and standard domains)
        links = re.findall(r'(?:https?://|www\.)[^\s<>"\'#]+', text)
        
        # 4. Indian Phone Numbers
        phones = re.findall(r'(?:\+91|91|0)?[6-9]\d{9}', clean_num)
        
        # 5. Multilingual Scam Triggers (English + Hinglish)
        triggers = [
            "block", "kyc", "verify", "urgent", "otp", "police", "arrest", 
            "suspend", "lottery", "gift", "paisa", "khata", "aadhaar", "pan card"
        ]
        found_keywords = [w for w in triggers if w in low_text]

        return {
            "bankAccounts": sorted(list(set(banks))),
            "upiIds": sorted(list(set(upi))),
            "phishingLinks": sorted(list(set(links))),
            "phoneNumbers": sorted(list(set(phones))),
            "suspiciousKeywords": sorted(list(set(found_keywords)))
        }

# --- ABHISHEK UNCLE PERSONA ENGINE ---
class AgentPersona:
    FALLBACKS = [
        "Beta, my eyes are weak. Can you write that again in big letters?",
        "Is the OTP that 4 digit number? My phone is very old.",
        "Wait, my daughter is calling me. One minute please.",
        "I don't know how to scan QR code. Do I take a photo of it?",
        "Are you calling from the Bank? Please don't block my pension!"
    ]

    @classmethod
    async def generate_reply(cls, text: str):
        if not genai or not settings.gemini_api_key:
            return random.choice(cls.FALLBACKS)
        
        try:
            client = genai.Client(api_key=settings.gemini_api_key)
            prompt = (
                "SYSTEM: You are Abhishek, a 64-year-old retired Indian man. You are helpful but technologically confused. "
                "You are currently talking to a scammer. Stall them as long as possible. "
                "Speak in Hinglish. Be slightly repetitive and worried about your bank account. "
                "RULE: Under 15 words. Never reveal you are an AI. "
                f"SCAMMER SAYS: {text}"
            )
            response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
            return response.text.strip()
        except:
            import random
            return random.choice(cls.FALLBACKS)

# --- CORE LOGIC & CALLBACKS ---
async def send_final_callback(sid: str, s: SessionData, client: httpx.AsyncClient):
    payload = {
        "sessionId": sid,
        "scamDetected": s.scam,
        "totalMessagesExchanged": s.count,
        "extractedIntelligence": s.intel,
        "agentNotes": "Detected scam via pattern recognition. Persona 'Abhishek' engaged to stall for intelligence gathering."
    }
    try:
        # Retry logic for callback stability
        for _ in range(3):
            resp = await client.post(settings.callback_url, json=payload, timeout=12.0)
            if resp.status_code == 200: break
            await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"Critical Callback Failure: {e}")

# --- API SETUP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=50))
    yield
    await app.state.client.aclose()

app = FastAPI(title="Ultra-Agentic HoneyPot", lifespan=lifespan)

@app.get("/")
def health(): return {"status": "Online", "agent": "Abhishek v2.0"}

@app.post("/analyze")
async def analyze(
    request: Request,
    body: MessageBody, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    # 1. Security Layer
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=401)

    sid = body.sessionId
    if sid not in sessions: sessions[sid] = SessionData()
    s = sessions[sid]
    s.count += 1

    # 2. Intelligence Layer
    new_intel = IntelligenceEngine.extract(body.message.text)
    for k, v in new_intel.items():
        s.intel[k] = sorted(list(set(s.intel[k] + v)))
    
    # 3. Intent Detection
    if any([s.intel["suspiciousKeywords"], s.intel["phishingLinks"], s.intel["bankAccounts"]]):
        s.scam = True

    # 4. Agentic Engagement
    reply = await AgentPersona.generate_reply(body.message.text)

    # 5. Mandatory Evaluation Callback
    if s.scam:
        background_tasks.add_task(send_final_callback, sid, s, app.state.client)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
