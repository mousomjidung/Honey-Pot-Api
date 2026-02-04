import os
import re
import asyncio
import logging
import random
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# --- GOOGLE GENAI SDK ---
try:
    from google import genai
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
logger = logging.getLogger("HoneyPot")

# --- DATA MODELS ---
class MessageDetail(BaseModel):
    sender: str
    text: str

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

sessions: Dict[str, SessionData] = {}

# --- INTELLIGENCE EXTRACTION ---
def extract_scam_intel(text: str) -> Dict[str, List[str]]:
    low_text = text.lower()
    clean_digits = re.sub(r'[^\d]', '', text)
    
    return {
        "bankAccounts": sorted(list(set(re.findall(r'\b\d{9,18}\b', text) + re.findall(r'\d{9,18}', clean_digits)))),
        "upiIds": sorted(list(set(re.findall(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}', text)))),
        "phishingLinks": sorted(list(set(re.findall(r'(?:https?://|www\.)[^\s<>"\'#]+', text)))),
        "phoneNumbers": sorted(list(set(re.findall(r'(?:\+91|91|0)?[6-9]\d{9}', clean_digits)))),
        "suspiciousKeywords": [w for w in ["block", "kyc", "otp", "verify", "urgent", "paisa", "khata"] if w in low_text]
    }

# --- AGENT BEHAVIOR ---
async def get_abhishek_reply(text: str):
    fallbacks = ["Beta, phone is hanging. Say again?", "Is the OTP a 4 digit number?"]
    if not genai or not settings.gemini_api_key:
        return random.choice(fallbacks)
    try:
        client = genai.Client(api_key=settings.gemini_api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash", 
            contents=f"You are Abhishek, 64yo Indian uncle. Reply in Hinglish to: {text}. Max 12 words."
        )
        return response.text.strip()
    except:
        return random.choice(fallbacks)

# --- THE MANDATORY CALLBACK (SECTION 12) ---
async def send_callback(sid: str, s: SessionData, client: httpx.AsyncClient):
    # This payload now exactly matches Section 12 requirements
    payload = {
        "sessionId": sid,
        "scamDetected": s.scam,
        "totalMessagesExchanged": s.count,
        "extractedIntelligence": {
            "bankAccounts": s.intel["bankAccounts"],
            "upiIds": s.intel["upiIds"],
            "phishingLinks": s.intel["phishingLinks"],
            "phoneNumbers": s.intel["phoneNumbers"],
            "suspiciousKeywords": s.intel["suspiciousKeywords"]
        },
        "agentNotes": "Automated detection: Scammer engaged using 'Abhishek' persona. Intelligence extracted via pattern matching."
    }
    try:
        for _ in range(3): # Retry 3 times
            res = await client.post(settings.callback_url, json=payload, timeout=5.0)
            if res.status_code == 200: 
                logger.info(f"Callback successful for {sid}")
                break
            await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"Callback failed: {e}")

# --- API ROUTES ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient()
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

@app.get("/")
def health(): return {"status": "running"}

@app.post("/analyze")
async def analyze(
    body: MessageBody, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=401)

    sid = body.sessionId
    if sid not in sessions: sessions[sid] = SessionData()
    s = sessions[sid]
    s.count += 1
    
    # Extract and Merge Intel
    new_intel = extract_scam_intel(body.message.text)
    for k, v in new_intel.items():
        s.intel[k] = sorted(list(set(s.intel[k] + v)))
    
    # Intent Confirmation
    if any([new_intel["suspiciousKeywords"], new_intel["phishingLinks"], new_intel["bankAccounts"]]):
        s.scam = True

    # Engagement
    reply = await get_abhishek_reply(body.message.text)

    # Trigger Callback in background if scam detected
    if s.scam:
        background_tasks.add_task(send_callback, sid, s, app.state.client)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
