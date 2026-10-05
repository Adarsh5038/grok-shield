from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI

from fastapi.responses import StreamingResponse

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel

import uuid

import re

import os

import json

from openai import OpenAI

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

from presidio_anonymizer import AnonymizerEngine

from presidio_anonymizer.entities import OperatorConfig

import fakeredis



app = FastAPI(title="Secure Grok Proxy")



# Allow the frontend to talk to the backend

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)



# In-memory secure vault for tokens

redis_client = fakeredis.FakeRedis(decode_responses=True)



# Point the client to the FREE Groq API

ai_client = OpenAI(

    api_key=os.environ.get("GROQ_API_KEY"),

    base_url="https://api.groq.com/openai/v1"

)



analyzer = AnalyzerEngine()



# --- Custom Pattern Recognizers ---



# 1. Names and phone numbers

name_pattern = Pattern("loose_name_pattern", regex=r"\b(?:my name is|i am|this is)\s+([a-zA-Z]+(?:\s+[a-zA-Z]+)?)\b", score=0.85)

phone_pattern = Pattern("loose_phone_pattern", regex=r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{10}\b", score=0.85)

name_phone_recognizer = PatternRecognizer(supported_entity="PERSON", patterns=[name_pattern])

phone_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[phone_pattern])



# 2. Universal Payment Cards

cc_pattern_1 = Pattern("broad_cc_digits", regex=r"\b(?:\d[ -]*?){12,19}\b", score=0.80)

cc_pattern_2 = Pattern("contextual_cc", regex=r"(?i)\b(?:credit\s*card|debit\s*card|card\s*number|cc|cvv)[\s:]*([0-9\-\s]{12,19})\b", score=0.95)

cc_recognizer = PatternRecognizer(supported_entity="CREDIT_CARD", patterns=[cc_pattern_1, cc_pattern_2])



# 3. API Keys

api_key_pattern = Pattern("api_token_pattern", regex=r"\b(?:sk-[a-zA-Z0-9_\-]{20,}|gsk_[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b", score=0.95)

api_key_recognizer = PatternRecognizer(supported_entity="API_KEY", patterns=[api_key_pattern])



# 4. Aadhaar Numbers

aadhaar_pattern = Pattern("aadhaar_pattern", regex=r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", score=0.85)

aadhaar_recognizer = PatternRecognizer(supported_entity="AADHAAR", patterns=[aadhaar_pattern])



 

# 5. Passwords (Updated to step over conversational filler words like "is")

password_pattern = Pattern(

    name="contextual_password",

    regex=r"(?i)\b(?:password|passwd|pwd|pass|secret)(?:\s+is)?[\s:=]+([^\s,;\.]+)",

    score=0.90

)

password_recognizer = PatternRecognizer(supported_entity="PASSWORD", patterns=[password_pattern])



# 6. Global, Regional & Contextual Addresses

address_pattern_us = Pattern(

    name="western_address",

    regex=r"(?i)\b\d{1,5}\s+(?:[a-zA-Z0-9.\-]+\s+){1,3}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Way|Ct|Court|Pl|Place)\b",

    score=0.85

)



address_pattern_global = Pattern(

    name="broad_address",

    regex=r"(?i)\b(?:room|flat|apt|apartment|house\s*no|plot\s*no|hostel|block|sector|phase|colony|nagar|vihar|marg|road)[\sA-Za-z0-9.,\-]{5,50}\b",

    score=0.85

)



pincode_pattern = Pattern(

    name="pincode_context",

    regex=r"(?i)\b(?:pin|pincode|zip|zipcode)[\s:-]*\d{5,6}\b",

    score=0.95

)



# NEW: Contextual Declarations

# Catches up to 4 words immediately following phrases like "address is" or "live in".

# It deliberately excludes periods so it stops scanning when a sentence ends.

address_context_pattern = Pattern(

    name="contextual_address",

    regex=r"(?i)\b(?:address is|live in|live at|residing at|location is)[\s:]+(?:[a-zA-Z0-9,-]+\s*){1,4}\b",

    score=0.90

)



address_recognizer = PatternRecognizer(

    supported_entity="ADDRESS",

    patterns=[

        address_pattern_us,

        address_pattern_global,

        pincode_pattern,

        address_context_pattern

    ]

)



# Register all custom recognizers

analyzer.registry.add_recognizer(name_phone_recognizer)

analyzer.registry.add_recognizer(phone_recognizer)

analyzer.registry.add_recognizer(cc_recognizer)

analyzer.registry.add_recognizer(api_key_recognizer)

analyzer.registry.add_recognizer(aadhaar_recognizer)

analyzer.registry.add_recognizer(password_recognizer)

analyzer.registry.add_recognizer(address_recognizer)



anonymizer = AnonymizerEngine()



MONITORED_ENTITIES = [

    "PERSON",

    "PHONE_NUMBER",

    "EMAIL_ADDRESS",

    "CREDIT_CARD",

    "IP_ADDRESS",

    "US_SSN",

    "API_KEY",

    "AADHAAR",

    "PASSWORD",

    "ADDRESS",

   # "LOCATION"    # Added built-in NLP location detection

]



class ChatRequest(BaseModel):

    text: str

    fun_mode: bool = False



def tokenize_and_store(real_text: str, entity_type: str) -> str:

    token_id = uuid.uuid4().hex[:4].upper()

    token = f"[{entity_type}_{token_id}]"

    redis_client.setex(token, 3600, real_text) # Expires in 1 hour

    return token



def stream_generator(safe_prompt_text, fun_mode):

    # Send the safe prompt to the frontend so the user can see what was scrubbed

    yield f"data: {json.dumps({'type': 'meta', 'safe_prompt': safe_prompt_text})}\n\n"

   

    # Define personality based on the UI toggle switch

    if fun_mode:

        persona = "You are an AI modeled after the Hitchhiker's Guide to the Galaxy. You are witty, slightly rebellious, and love a good joke while answering questions. You will encounter bracketed tokens like [PERSON_XXXX]—always keep these exact tokens intact in your response."

    else:

        persona = "You are a maximally truth-seeking AI. You provide insightful, highly accurate, and direct answers. You will encounter bracketed tokens like [PERSON_XXXX]—always keep these exact tokens intact in your response."

   

    # Request the stream from Groq

    stream_response = ai_client.chat.completions.create(

        model="openai/gpt-oss-20b",

        messages=[

            {"role": "system", "content": persona},

            {"role": "user", "content": safe_prompt_text}

        ],

        stream=True

    )

   

    buffer = ""

    for chunk in stream_response:

        delta = chunk.choices[0].delta.content

        if delta:

            buffer += delta

           

            # Rehydration logic: Check if a token is complete before yielding

            if "[" in buffer:

                tokens = re.findall(r"\[[A-Z_]+_[A-Z0-9]+\]", buffer)

                for t in tokens:

                    real_val = redis_client.get(t)

                    if real_val:

                        buffer = buffer.replace(t, real_val)

               

                last_open = buffer.rfind("[")

                last_close = buffer.rfind("]")

                if last_open > last_close:

                    safe_to_yield = buffer[:last_open]

                    buffer = buffer[last_open:]

                    if safe_to_yield:

                        yield f"data: {json.dumps({'type': 'token', 'content': safe_to_yield})}\n\n"

                    continue

            yield f"data: {json.dumps({'type': 'token', 'content': buffer})}\n\n"

            buffer = ""

           

    # Flush any remaining text in the buffer

    if buffer:

        tokens = re.findall(r"\[[A-Z_]+_[A-Z0-9]+\]", buffer)

        for t in tokens:

            real_val = redis_client.get(t)

            if real_val:

                buffer = buffer.replace(t, real_val)

        yield f"data: {json.dumps({'type': 'token', 'content': buffer})}\n\n"



@app.post("/api/secure-chat")

def secure_chat(request: ChatRequest):

    # 1. Analyze text for PII

    results = analyzer.analyze(text=request.text, entities=MONITORED_ENTITIES, language='en')

   

    # 2. Setup operators to tokenize and vault the data

    operators = {e: OperatorConfig("custom", {"lambda": lambda x, ent=e: tokenize_and_store(x, ent)}) for e in MONITORED_ENTITIES}

   

    # 3. Anonymize the prompt

    safe_prompt = anonymizer.anonymize(text=request.text, analyzer_results=results, operators=operators)

   

    # 4. Stream response back to frontend

    return StreamingResponse(

        stream_generator(safe_prompt.text, request.fun_mode),

        media_type="text/event-stream"

    ) 

