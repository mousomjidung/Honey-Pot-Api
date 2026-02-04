import os
import re
import logging
import random
import asyncio
from collections import OrderedDict
from typing import List, Optional, Dict, Any, Pattern, Set

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks, Header, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- PYDANTIC V2 UPDATES ---
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# New Google GenAI SDK (v1)
try:
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore
except Exception:
    genai = None
    types = None

# Load environment variables
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
    max_incoming_text_len: int = Field(2000, alias="MAX_INCOMING_TEXT_LEN")

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

settings = Settings()

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("HoneyPot")

# --- PATTERNS & INTELLIGENCE ---
class IntelExtractor:
    PATTERNS: Dict[str, Pattern] = {
        "upi": re.compile(r"[a-zA-Z0-9\.\-_]{3,}@[a-zA-Z]{3,}"),
        "phone": re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}"),
        "url": re.compile(r"(?:https?://|www\.)[^\s<>\"']+"),
        "bank": re.compile(r"\b\d{9,18}\b"),
        "filter": re.compile(r"(gmail|yahoo|hotmail|outlook)"),
    }
    TRIGGERS: Set[str] = {"block", "suspend", "kyc", "expire", "urgent", "police", "verify", "otp", "cbi", "arrest"}

    @classmethod
    def extract(cls, text: str) -> Dict[str, List[str]]:
        if not text:
            return {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []}
        text_lower = text.lower()
        bank_accounts = [n for n in cls.PATTERNS["bank"].findall(text) if len(n) > 8]
        upi_ids = [u for u in cls.PATTERNS["upi"].findall(text) if not cls.PATTERNS["filter"].search(u)]
        raw_links = cls.PATTERNS["url"].findall(text)
        phishing_links = [link.rstrip(".,!?;:") for link in raw_links]
        phone_numbers = cls.PATTERNS["phone"].findall(text)
        suspicious_keywords = [w for w in cls.TRIGGERS if w in text_lower]
        return {
            "bankAccounts": sorted(list(set(bank_accounts))),
            "upiIds": sorted(list(set(upi_ids))),
            "phishingLinks": sorted(list(set(phishing_links))),
            "phoneNumbers": sorted(list(set(phone_numbers))),
            "suspiciousKeywords": sorted(list(set(suspicious_keywords))),
        }

# --- AI HANDLER ---
class AIHandler:
    FALLBACK_OPTIONS = [
        "Beta, SMS folder is empty. Resend please?",
        "Is the OTP the 4 digit number on the back of the card?",
        "My phone memory is full, I am deleting photos. Wait.",
        "Server down dikha raha hai.",
        "How to scan QR code? Do I take a photo?",
        "Sir please! Do not block, I am a poor pensioner.",
        "Hello? Can you hear me?",
    ]

    def __init__(self, gemini_api_key: Optional[str], model_candidates: List[str]):
        self.client = None
        self.gemini_api_key = gemini_api_key
        self.model_candidates = model_candidates

    def initialize_client(self):
        if not self.gemini_api_key:
            return
        if genai is None:
            return
        try:
            self.client = genai.Client(api_key=self.gemini_api_key)
        except Exception:
            self.client = None

    def get_fallback(self) -> str:
        return random.choice(self.FALLBACK_OPTIONS)

    async def get_reply(self, history: List[Dict[str, Any]], text: str) -> str:
        if not self.client:
            return self.get_fallback()

        transcript = ""
        for msg in (history or [])[-6:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "Abhishek"
            content = msg.get("text", "")
            if content:
                transcript += f"{role}: {content}\n"
        transcript += f"Scammer: {text}\nAbhishek:"

        prompt = (
            "You are Abhishek, a 64-year-old Indian uncle.\n"
            "Context: You are identifying a scammer. Stall them.\n"
            "Style: Scared, confused, Hinglish.\n"
            "RULES: Keep it SHORT (under 15 words). Act dumb. No AI mention.\n"
            f"CHAT HISTORY:\n{transcript}"
        )

        for model_name in self.model_candidates:
            try:
                response = self.client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        safety_settings=[
                            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                        ]
                    ),
                )
                text_out = getattr(response, "text", None) or (response.output_text if hasattr(response, "output_text") else None)
                if text_out:
                    return str(text_out).strip().replace("Abhishek:", "").strip()
            except Exception:
                continue
        return self.get_fallback()

# --- SESSION ---
class SessionData(BaseModel):
    scam: bool = False
    intel: Dict[str, List[str]] = Field(default_factory=lambda: {
        "bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []
    })
    count: int = 0

class SessionManager:
    def __init__(self, max_sessions: int = 500):
        self._sessions: "OrderedDict[str, SessionData]" = OrderedDict()
        self.max_sessions = max_sessions
        self._lock = asyncio.Lock()

    async def get_session(self, sid: str) -> SessionData:
        async with self._lock:
            if sid in self._sessions:
                self._sessions.move_to_end(sid)
                return self._sessions[sid]
            if len(self._sessions) >= self.max_sessions:
                self._sessions.popitem(last=False)
            sd = SessionData()
            self._sessions[sid] = sd
            return sd

    async def update_session(self, sid: str, intel: Dict[str, List[str]]):
        async with self._lock:
            session = self._sessions.get(sid)
            if not session:
                session = SessionData()
                self._sessions[sid] = session
            session.count += 1
            for k, v in intel.items():
                if isinstance(v, list):
                    current = session.intel.get(k, [])
                    session.intel[k] = sorted(list(set(current + v)))
            if intel.get("suspiciousKeywords") or intel.get("phishingLinks"):
                session.scam = True
            self._sessions.move_to_end(sid)

# --- APP SETUP ---
ai_handler = AIHandler(settings.gemini_api_key, settings.model_candidates)
session_manager = SessionManager(settings.max_sessions)

@asynccontextmanager
async def lifespan(app: FastAPI):
    ai_handler.initialize_client()
    app.state.client = httpx.AsyncClient(timeout=10.0)
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for Hackathon testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- PERMISSIVE REQUEST MODEL ---
class MessageBody(BaseModel):
    sessionId: Optional[str] = Field("test-session")
    message: Optional[Dict[str, Any]] = None
    text: Optional[str] = None
    input: Optional[str] = None
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    # CRITICAL: Ignore extra fields (metadata, etc.) to prevent validation errors
    model_config = {"extra": "ignore"}

    @field_validator("text", "input", mode="before")
    @classmethod
    def strip_text(cls, v: Any) -> Any:
        if v is None: return None
        return str(v).strip()

class AnalyzeResponse(BaseModel):
    status: str
    reply: str

# --- CALLBACK ---
def sanitize_for_callback(payload: Dict[str, Any], max_len: int = 1000) -> Dict[str, Any]:
    # Simplified sanitizer
    return payload 

async def send_callback(sid: str, session: SessionData, client: httpx.AsyncClient):
    payload = {
        "sessionId": sid,
        "scamDetected": session.scam,
        "totalMessagesExchanged": session.count,
        "extractedIntelligence": session.intel,
        "agentNotes": "Automated HoneyPot update.",
    }
    try:
        await client.post(settings.callback_url, json=payload, timeout=10.0)
    except Exception as e:
        logger.error(f"Callback failed: {e}")

# --- ENDPOINTS ---

@app.get("/", response_model=Dict[str, str])
def home():
    return {"status": "running", "mode": "Agentic HoneyPot (Abhishek)"}

# FIX: Add a GET handler for /analyze to satisfy connectivity checks (HEAD requests)
@app.get("/analyze")
def analyze_health_check():
    return {"status": "active", "message": "Use POST to send messages"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_post(
    body: MessageBody,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

    # Robust text extraction
    incoming_text = None
    if isinstance(body.message, dict):
        incoming_text = body.message.get("text")
    if not incoming_text:
        incoming_text = body.text
    if not incoming_text:
        incoming_text = body.input
    
    # If still empty, assume simple ping or empty message
    if not incoming_text:
        return AnalyzeResponse(status="success", reply="Hello? Who is this?")

    sid = body.sessionId or "test-session"
    
    # Processing
    session = await session_manager.get_session(sid)
    new_intel = IntelExtractor.extract(incoming_text)
    await session_manager.update_session(sid, new_intel)
    
    # Generate Reply
    reply_text = await ai_handler.get_reply(body.conversationHistory, incoming_text)

    # Callback Logic
    send_cb = session.scam or (not settings.callback_only_on_scam and session.count > 0)
    if send_cb:
        background_tasks.add_task(send_callback, sid, session, app.state.client)

    return AnalyzeResponse(status="success", reply=reply_text)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
