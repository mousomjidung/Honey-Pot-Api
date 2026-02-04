import os
import re
import asyncio
import logging
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# --- GOOGLE GENAI SETUP ---
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None

load_dotenv()

# --- CONFIGURATION ---
class Settings(BaseSettings):
    gemini_api_key: Optional[str] = Field(None, alias="GEMINI_API_KEY")
    required_api_key: str = "zero-day-101" # Your x-api-key
    callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HoneyPot")

# --- DATA MODELS (Section 6 Compliance) ---
class MessageDetail(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class MessageBody(BaseModel):
    model_config = ConfigDict(extra="ignore") # Ignores 'metadata'
    sessionId: str
    message: MessageDetail
    conversationHistory: List[Dict[str, Any]] = []

class SessionData(BaseModel):
    scam: bool = False
    count: int = 0
    intel: Dict[str, List[str]] = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }

# Memory storage for hackathon (Reset on Render restart)
sessions: Dict[str, SessionData] = {}

# --- INTELLIGENCE EXTRACTION (Section 12 Compliance) ---
def extract_scam_intel(text: str) -> Dict[str, List[str]]:
    text_lower = text.lower()
    # Remove spaces/dashes for better number matching
    clean_digits = re.sub(r'[\s\-]', '', text)
    
    return {
        "bankAccounts": sorted(list(set(re.findall(r'\b\d{9,18}\b', clean_digits)))),
        "upiIds": sorted(list(set(re.findall(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}', text)))),
        "phishingLinks": sorted(list(set(re.findall(r'(?:https?://|www\.)[^\s<>"\'#]+', text)))),
        "phoneNumbers": sorted(list(set(re.findall(r'(?:\+91|91|0)?[6-9]\d{9}', clean_digits)))),
        "suspiciousKeywords": [w for w in ["block", "kyc", "verify", "urgent", "otp", "police", "arrest", "suspend"] if w in text_lower]
    }

# --- AGENT BEHAVIOR (Section 7 Persona) ---
async def get_abhishek_reply(history: list, current_text: str):
    if not genai or not settings.gemini_api_key:
        return "Beta, phone screen is broken. Can you send again?"
    
    client = genai.Client(api_key=settings.gemini_api_key)
    # Abhishek: 64yo Indian Uncle persona
    prompt = (
        "You are Abhishek, a 64-year-old Indian man who is not tech-savvy. "
        "A scammer is messaging you. Act confused, slightly scared, and talkative. "
        "Use Hinglish (Hindi + English). Keep it under 15 words. "
        f"Scammer said: {current_text}"
    )
    
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash", 
            contents=prompt
        )
        return response.text.strip().replace("Abhishek:", "").strip()
    except Exception as e:
        logger.error(f"AI Error: {e}")
        return "Beta, server down dikha raha hai. Kya karu?"

# --- CALLBACK LOGIC ---
async def perform_callback(sid: str, s: SessionData, http_client: httpx.AsyncClient):
    payload = {
        "sessionId": sid,
        "scamDetected": s.scam,
        "totalMessagesExchanged": s.count,
        "extractedIntelligence": s.intel,
        "agentNotes": "Persona: Abhishek (Uncle). Urgency tactics detected. Intelligence extracted via regex patterns."
    }
    try:
        res = await http_client.post(settings.callback_url, json=payload, timeout=10.0)
        logger.info(f"Callback status for {sid}: {res.status_code}")
    except Exception as e:
        logger.error(f"Callback failed: {e}")

# --- APP SETUP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient()
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

@app.get("/")
def health_check():
    return {"status": "running", "agent": "Abhishek (HoneyPot)"}

@app.post("/analyze")
async def analyze_message(
    body: MessageBody, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    # 1. Auth Check
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    sid = body.sessionId
    incoming_text = body.message.text

    # 2. Session Management
    if sid not in sessions:
        sessions[sid] = SessionData()
    s = sessions[sid]
    s.count += 1

    # 3. Extraction
    new_intel = extract_scam_intel(incoming_text)
    for key, values in new_intel.items():
        s.intel[key] = sorted(list(set(s.intel[key] + values)))
    
    # 4. Detect Scam Intent
    if s.intel["suspiciousKeywords"] or s.intel["phishingLinks"] or s.intel["bankAccounts"]:
        s.scam = True

    # 5. AI Engagement
    reply = await get_abhishek_reply(body.conversationHistory, incoming_text)

    # 6. Final Result Callback (Asynchronous)
    if s.scam:
        background_tasks.add_task(perform_callback, sid, s, app.state.client)

    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    import uvicorn
    # Important: Use dynamic port for Render
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
