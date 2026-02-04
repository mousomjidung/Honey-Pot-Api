import os
import re
import logging
import random
import asyncio
from collections import OrderedDict
from typing import List, Optional, Dict, Any, Pattern, Set
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks, Header, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- PYDANTIC V2 UPDATES ---
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Google GenAI SDK
try:
    from google import genai
    from google.genai import types
except Exception:
    genai = None
    types = None

load_dotenv()

# --- CONFIGURATION ---
class Settings(BaseSettings):
    gemini_api_key: Optional[str] = Field(None, alias="GEMINI_API_KEY")
    callback_url: str = Field("https://hackathon.guvi.in/api/updateHoneyPotFinalResult", alias="CALLBACK_URL")
    model_candidates: List[str] = Field(
        default_factory=lambda: ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
        alias="MODEL_CANDIDATES",
    )
    required_api_key: str = Field("zero-day-101", alias="REQUIRED_API_KEY")
    max_sessions: int = Field(500, alias="MAX_SESSIONS")
    callback_only_on_scam: bool = Field(True, alias="CALLBACK_ONLY_ON_SCAM")
    allowed_origins: Optional[str] = Field("http://localhost", alias="ALLOWED_ORIGINS")
    
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

settings = Settings()

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("HoneyPot")

# --- INTELLIGENCE LOGIC ---
class IntelExtractor:
    PATTERNS = {
        "upi": re.compile(r"[a-zA-Z0-9\.\-_]{3,}@[a-zA-Z]{3,}"),
        "phone": re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}"),
        "url": re.compile(r"(?:https?://|www\.)[^\s<>\"']+"),
        "bank": re.compile(r"\b\d{9,18}\b"),
    }
    TRIGGERS = {"block", "suspend", "kyc", "expire", "urgent", "police", "verify", "otp", "cbi", "arrest"}

    @classmethod
    def extract(cls, text: str) -> Dict[str, List[str]]:
        if not text:
            return {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []}
        text = str(text).lower()
        return {
            "bankAccounts": sorted(list(set([n for n in cls.PATTERNS["bank"].findall(text) if len(n) > 8]))),
            "upiIds": sorted(list(set([u for u in cls.PATTERNS["upi"].findall(text) if "gmail" not in u]))),
            "phishingLinks": sorted(list(set([l.rstrip(".,") for l in cls.PATTERNS["url"].findall(text)]))),
            "phoneNumbers": sorted(list(set(cls.PATTERNS["phone"].findall(text)))),
            "suspiciousKeywords": sorted(list(set([w for w in cls.TRIGGERS if w in text]))),
        }

# --- AI HANDLER ---
class AIHandler:
    async def get_reply(self, history: list, text: str) -> str:
        # Simplified for robustness
        client = None
        if settings.gemini_api_key and genai:
            try:
                client = genai.Client(api_key=settings.gemini_api_key)
            except: pass
        
        if client:
            try:
                prompt = f"Act as Abhishek, a 64yo Indian uncle being scammed. Reply to: {text}. Keep it short."
                response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
                if response.text: return response.text.replace("Abhishek:", "").strip()
            except: pass
        
        return "Beta, I do not understand. My son will call you."

ai_handler = AIHandler()

# --- APP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(timeout=10.0)
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CALLBACK ---
async def send_callback(sid: str, intel: dict, count: int, client: httpx.AsyncClient):
    payload = {
        "sessionId": sid,
        "scamDetected": True, # Always true if we are engaging
        "totalMessagesExchanged": count,
        "extractedIntelligence": intel,
        "agentNotes": "Automated HoneyPot update."
    }
    try:
        await client.post(settings.callback_url, json=payload, timeout=5.0)
        logger.info(f"Callback sent for {sid}")
    except Exception as e:
        logger.error(f"Callback failed: {e}")

# --- ENDPOINTS ---
@app.get("/")
def home():
    return {"status": "running"}

@app.get("/analyze") # Handle GET/HEAD pings
def analyze_ping():
    return {"status": "active"}

# NUCLEAR FIX: Use Request object directly to bypass validation errors
@app.post("/analyze")
async def analyze_post(request: Request, background_tasks: BackgroundTasks):
    # 1. Check API Key Manually
    api_key = request.headers.get("x-api-key")
    if api_key != settings.required_api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Parse JSON safely
    try:
        body = await request.json()
        logger.info(f"DEBUG - RECEIVED BODY: {body}") # <--- LOOK AT THIS IN LOGS
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # 3. Extract Fields Manually (Forgiving logic)
    # Handle sessionId being snake_case OR camelCase
    sid = body.get("sessionId") or body.get("session_id") or "test-session"
    
    # Handle message structure (nested vs flat)
    incoming_text = ""
    msg_obj = body.get("message")
    if isinstance(msg_obj, dict):
        incoming_text = msg_obj.get("text", "")
    elif isinstance(msg_obj, str):
        incoming_text = msg_obj
    else:
        incoming_text = body.get("text") or body.get("input") or ""

    # 4. Process
    intel = IntelExtractor.extract(str(incoming_text))
    reply = await ai_handler.get_reply([], str(incoming_text))

    # 5. Callback
    background_tasks.add_task(send_callback, sid, intel, 1, app.state.client)

    # 6. Return standard response
    return {"status": "success", "reply": reply}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
