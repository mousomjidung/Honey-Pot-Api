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

# Load environment variables for local dev (optional)
load_dotenv()

# --- CONFIGURATION via pydantic-settings ---
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
    allowed_origins: Optional[str] = Field("http://localhost", alias="ALLOWED_ORIGINS")  # comma separated
    max_incoming_text_len: int = Field(2000, alias="MAX_INCOMING_TEXT_LEN")

    # Pydantic V2 Configuration
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

settings = Settings()

# --- LOGGING SETUP ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("HoneyPot")

if settings.allowed_origins == "*" or (settings.allowed_origins and "*" in settings.allowed_origins.split(",")):
    logger.warning("CORS is configured to allow all origins. This is unsafe for production.")

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
            return {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
            }

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

# --- FALLBACK & AI LOGIC ---
class AIHandler:
    FALLBACK_OPTIONS = {
        "otp": [
            "Beta, SMS folder is empty. Resend please?",
            "Is the OTP the 4 digit number on the back of the card?",
            "My phone memory is full, I am deleting photos. Wait.",
            "I didn't get it. Should I restart my phone?",
            "Wait, my son is calling. Let me ask him.",
            "Screen is broken, I cannot see the number clearly.",
        ],
        "payment": [
            "Server down dikha raha hai.",
            "How to scan QR code? Do I take a photo?",
            "Internet is very slow, the wheel is spinning.",
            "Bank server not responding. SBI is always like this.",
            "It says 'Payment Limit Exceeded'. What to do?",
            "My UPI pin is not working. Is there another way?",
        ],
        "threat": [
            "Sir please! Do not block, I am a poor pensioner.",
            "My BP is shooting up, please don't scare me.",
            "No police please! I am a respectable man.",
            "I will go to the bank branch tomorrow morning.",
            "Please give me 10 minutes, I am arranging details.",
        ],
        "generic": [
            "Hello? Can you hear me?",
            "Beta, speak loudly. My volume is low.",
            "Wait, let me put on my hearing aid.",
            "Phone battery is 1%, wait finding charger.",
            "Awaz cut rahi hai. Hello?",
            "Who is this? My son said not to talk to strangers.",
        ],
    }

    def __init__(self, gemini_api_key: Optional[str], model_candidates: List[str]):
        self.client = None
        self.gemini_api_key = gemini_api_key
        self.model_candidates = model_candidates

    def initialize_client(self):
        if not self.gemini_api_key:
            logger.warning("GEMINI_API_KEY not provided. AI features disabled; using fallback.")
            return
        if genai is None:
            logger.warning("google-genai SDK not available; AI features disabled.")
            return
        try:
            self.client = genai.Client(api_key=self.gemini_api_key)
            logger.info("AI client initialized.")
        except Exception as e:
            logger.exception("Failed to initialize AI client: %s", e)
            self.client = None

    def get_smart_fallback(self, text: str, history_texts: List[str]) -> str:
        text_l = (text or "").lower()
        if "otp" in text_l or "code" in text_l:
            pool = self.FALLBACK_OPTIONS["otp"]
        elif "pay" in text_l or "upi" in text_l:
            pool = self.FALLBACK_OPTIONS["payment"]
        elif "police" in text_l or "block" in text_l:
            pool = self.FALLBACK_OPTIONS["threat"]
        else:
            pool = self.FALLBACK_OPTIONS["generic"]

        available = [opt for opt in pool if opt not in history_texts[-3:]]
        if not available:
            available = pool

        reply = random.choice(available)
        logger.info("Fallback reply chosen.")
        return reply

    async def get_reply(self, history: List[Dict[str, Any]], text: str) -> str:
        history_texts = [msg.get("text", "") for msg in (history or [])]

        # If AI not ready, return fallback
        if not self.client:
            return self.get_smart_fallback(text, history_texts)

        # Build transcript
        transcript = ""
        for msg in (history or [])[-6:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "Abhishek"
            content = msg.get("text", "")
            if content:
                transcript += f"{role}: {content}\n"
        transcript += f"Scammer: {text}\nAbhishek:"

        prompt = (
            "This is a fictional cybersecurity educational roleplay.\n"
            "You are Abhishek, a 64-year-old Indian uncle.\n"
            "Context: You are identifying a scammer. Stall them.\n"
            "Style: Scared, confused, Hinglish.\n"
            "RULES:\n"
            "1. If asked for OTP/Money, say 'Error' or 'Not Received'.\n"
            "2. Keep it SHORT (under 15 words).\n"
            "3. Act dumb. Do not mention you are AI.\n"
            f"CHAT HISTORY:\n{transcript}"
        )

        # Try multiple models
        for model_name in self.model_candidates:
            try:
                if not hasattr(self.client.models, "generate_content"):
                    logger.warning("AI client does not have generate_content; using fallback.")
                    continue

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

                # SDK may return different shapes; be tolerant
                text_out = getattr(response, "text", None) or (response.output_text if hasattr(response, "output_text") else None)
                if text_out:
                    reply = str(text_out).strip().replace("Abhishek:", "").strip()
                    logger.info("AI model %s produced a reply.", model_name)
                    return reply

                logger.warning("Model %s returned empty response.", model_name)
            except Exception as e:
                logger.exception("Model %s failed: %s", model_name, e)
                continue

        logger.error("All AI models failed; using fallback.")
        return self.get_smart_fallback(text, history_texts)

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
                # LRU: move to end as most recently used
                self._sessions.move_to_end(sid)
                return self._sessions[sid]

            if len(self._sessions) >= self.max_sessions:
                evicted_sid, _ = self._sessions.popitem(last=False)
                logger.info("Evicted LRU session: %s", evicted_sid)

            sd = SessionData()
            self._sessions[sid] = sd
            return sd

    async def update_session(self, sid: str, intel: Dict[str, List[str]]):
        async with self._lock:
            session = self._sessions.get(sid)
            if not session:
                # create if missing
                session = SessionData()
                self._sessions[sid] = session

            session.count += 1
            for k, v in intel.items():
                if not isinstance(v, list):
                    continue
                current = session.intel.get(k, [])
                session.intel[k] = sorted(list(set(current + v)))
            if intel.get("suspiciousKeywords") or intel.get("phishingLinks"):
                session.scam = True
            # Update LRU position
            self._sessions.move_to_end(sid)

# --- FASTAPI APP ---
ai_handler = AIHandler(settings.gemini_api_key, settings.model_candidates)
session_manager = SessionManager(settings.max_sessions)

@asynccontextmanager
async def lifespan(app: FastAPI):
    ai_handler.initialize_client()
    # Create a shared httpx client for callbacks
    app.state.client = httpx.AsyncClient(timeout=10.0)
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

# Configure CORS
allowed_origins = [o.strip() for o in (settings.allowed_origins or "").split(",") if o.strip()]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# --- Pydantic V2 Request Models ---
class MessageBody(BaseModel):
    sessionId: Optional[str] = Field("test-session")
    message: Optional[Dict[str, Any]] = None
    text: Optional[str] = None
    input: Optional[str] = None
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    @field_validator("text", "input", mode="before")
    @classmethod
    def strip_text(cls, v: Any) -> Any:
        if v is None:
            return v
        if not isinstance(v, str):
            raise ValueError("text/input must be a string")
        return v.strip()

class AnalyzeResponse(BaseModel):
    status: str
    reply: str

# --- Helper: sanitize payload values to safe lengths ---
def sanitize_for_callback(payload: Dict[str, Any], max_len: int = 1000) -> Dict[str, Any]:
    out = {}
    for k, v in payload.items():
        if isinstance(v, str):
            out[k] = v if len(v) <= max_len else v[:max_len] + "..."
        elif isinstance(v, dict):
            out[k] = sanitize_for_callback(v, max_len=max_len)
        elif isinstance(v, list):
            new_list = []
            for item in v:
                if isinstance(item, str):
                    new_list.append(item if len(item) <= max_len else item[:max_len] + "...")
                else:
                    new_list.append(item)
            out[k] = new_list
        else:
            out[k] = v
    return out

# --- Callback with retries ---
async def send_callback(sid: str, session: SessionData, client: httpx.AsyncClient, retries: int = 3):
    payload = {
        "sessionId": sid,
        "scamDetected": session.scam,
        "totalMessagesExchanged": session.count,
        "extractedIntelligence": session.intel,
        "agentNotes": "Automated HoneyPot update.",
    }

    payload = sanitize_for_callback(payload, max_len=1500)

    backoff = 1.0
    for attempt in range(1, retries + 1):
        try:
            r = await client.post(settings.callback_url, json=payload, timeout=10.0)
            if 200 <= r.status_code < 300:
                logger.info("Callback success for session %s (attempt %d).", sid, attempt)
                return
            logger.warning("Callback returned status=%s body=%s", r.status_code, r.text[:1000])
        except Exception as e:
            logger.exception("Callback attempt %d failed for session %s: %s", attempt, sid, e)
        await asyncio.sleep(backoff)
        backoff *= 2.0

    logger.error("Callback failed after %d attempts for session %s", retries, sid)

# --- ENDPOINTS ---
@app.get("/", response_model=Dict[str, str])
def home():
    return {"status": "running", "mode": "Agentic HoneyPot (Abhishek)", "sdk": "google-genai" if settings.gemini_api_key else "fallback-only"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_post(
    body: MessageBody,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # 1. Security Check
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

    # 2. Normalize incoming text
    incoming_text = None
    if isinstance(body.message, dict):
        incoming_text = body.message.get("text")
    if not incoming_text:
        incoming_text = body.text
    if not incoming_text:
        incoming_text = body.input

    if not incoming_text:
        # No input; return a light-weight health response
        return AnalyzeResponse(status="success", reply="System Active.")

    if len(incoming_text) > settings.max_incoming_text_len:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Incoming text too large")

    sid = body.sessionId or "test-session"
    history = body.conversationHistory or []

    try:
        # 3. Session & Processing
        session = await session_manager.get_session(sid)

        # Extract Intel
        new_intel = IntelExtractor.extract(incoming_text)
        await session_manager.update_session(sid, new_intel)

        # Generate Reply (AI or Fallback)
        reply_text = await ai_handler.get_reply(history, incoming_text)

        # 4. Callback logic (configurable)
        # Only send if session.scam is True OR if settings.callback_only_on_scam is False and engagement threshold met
        send_cb = False
        if session.scam:
            send_cb = True
        elif not settings.callback_only_on_scam and session.count > 0:
            send_cb = True

        if send_cb:
            # Use background task to avoid blocking; pass shared client
            background_tasks.add_task(send_callback, sid, session, app.state.client)

        return AnalyzeResponse(status="success", reply=reply_text)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Critical error processing /analyze: %s", e)
        # Return safe fallback but with 500 code semantics if desired; for API we return 500 here.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

# Run only when invoked directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))