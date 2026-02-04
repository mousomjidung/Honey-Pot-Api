import os
import re
import logging
import random
import asyncio
from collections import OrderedDict
from typing import List, Optional, Dict, Any, Set

from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# New Google GenAI SDK (v1)
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
    callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    required_api_key: str = "zero-day-101" # Ensure this matches your provided key
    model_candidates: List[str] = ["gemini-2.0-flash", "gemini-1.5-flash"]
    
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

settings = Settings()

# --- REQUEST MODELS (Section 6 Compliance) ---
class MessageDetail(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class MessageBody(BaseModel):
    model_config = ConfigDict(extra="ignore") # Crucial for 'metadata' field
    
    sessionId: str
    message: MessageDetail
    conversationHistory: List[Dict[str, Any]] = []

class AnalyzeResponse(BaseModel):
    status: str
    reply: str

# --- INTEL EXTRACTION ---
class IntelExtractor:
    PATTERNS = {
        "upi": re.compile(r"[a-zA-Z0-9\.\-_]{3,}@[a-zA-Z]{3,}"),
        "phone": re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}"),
        "url": re.compile(r"(?:https?://|www\.)[^\s<>\"']+"),
        "bank": re.compile(r"\b\d{9,18}\b"),
    }
    TRIGGERS = {"block", "suspend", "kyc", "verify", "otp", "arrest", "urgent", "lottery", "gift"}

    @classmethod
    def extract(cls, text: str) -> Dict[str, List[str]]:
        text_lower = text.lower()
        return {
            "bankAccounts": sorted(list(set(cls.PATTERNS["bank"].findall(text)))),
            "upiIds": sorted(list(set(cls.PATTERNS["upi"].findall(text)))),
            "phishingLinks": sorted(list(set(cls.PATTERNS["url"].findall(text)))),
            "phoneNumbers": sorted(list(set(cls.PATTERNS["phone"].findall(text)))),
            "suspiciousKeywords": [w for w in cls.TRIGGERS if w in text_lower]
        }

# --- SESSION & APP STATE ---
class SessionData(BaseModel):
    scam: bool = False
    intel: Dict[str, List[str]] = {"bankAccounts":[], "upiIds":[], "phishingLinks":[], "phoneNumbers":[], "suspiciousKeywords":[]}
    count: int = 0

sessions: Dict[str, SessionData] = {}

# --- AGENTIC BEHAVIOR (Section 7) ---
async def get_ai_reply(history: list, current_text: str):
    if not genai or not settings.gemini_api_key:
        return "Beta, processing slow hai. What did you say?"
    
    client = genai.Client(api_key=settings.gemini_api_key)
    prompt = (
        "Role: Abhishek, 64yo Indian Uncle. Scared but talkative. "
        "Task: Stall a scammer. Use Hinglish. Keep it under 15 words. "
        f"Scammer said: {current_text}"
    )
    
    try:
        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        return response.text.strip()
    except:
        return "Kya? My phone is hanging. Please tell again."

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient()
    yield
    await app.state.client.aclose()

app = FastAPI(lifespan=lifespan)

# --- ENDPOINTS ---

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    body: MessageBody, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    # 1. Auth Check
    if x_api_key != settings.required_api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    sid = body.sessionId
    incoming_text = body.message.text

    # 2. Get/Update Session
    if sid not in sessions:
        sessions[sid] = SessionData()
    
    s = sessions[sid]
    s.count += 1
    
    # 3. Extraction & Scam Detection
    new_intel = IntelExtractor.extract(incoming_text)
    for k, v in new_intel.items():
        s.intel[k] = sorted(list(set(s.intel[k] + v)))
    
    if s.intel["suspiciousKeywords"] or s.intel["phishingLinks"]:
        s.scam = True

    # 4. Agent Engagement
    reply = await get_ai_reply(body.conversationHistory, incoming_text)

    # 5. Mandatory Callback (Section 12)
    # Logic: If it's a scam, send updates to the platform
    if s.scam:
        callback_payload = {
            "sessionId": sid,
            "scamDetected": True,
            "totalMessagesExchanged": s.count,
            "extractedIntelligence": s.intel,
            "agentNotes": "Automated detection: Scammer using high-pressure tactics."
        }
        background_tasks.add_task(
            app.state.client.post, 
            settings.callback_url, 
            json=callback_payload
        )

    return AnalyzeResponse(status="success", reply=reply)
