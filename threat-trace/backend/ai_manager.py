import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

GEMINI_KEYS = [
    os.getenv("GEMINI_API_KEY"),
    os.getenv("GEMINI_API_KEY_2"),
    os.getenv("GEMINI_API_KEY_3"),
]

GEMINI_KEYS = [k for k in GEMINI_KEYS if k]

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

GROQ_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_2"),
]

GROQ_KEYS = [k for k in GROQ_KEYS if k]

GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

OPENROUTER_KEYS = [
    os.getenv("OPENROUTER_API_KEY"),
    os.getenv("OPENROUTER_API_KEY_2"),
]

OPENROUTER_KEYS = [k for k in OPENROUTER_KEYS if k]

OPENROUTER_MODEL = os.getenv(
    "OPENROUTER_MODEL",
    "openrouter/free"
)

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5:3b"
)

AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "30"))

PRIMARY_PROVIDER = os.getenv(
    "AI_PRIMARY_PROVIDER",
    "gemini"
).lower()

FALLBACK_ENABLED = os.getenv(
    "AI_FALLBACK_ENABLED",
    "true"
).lower() == "true"


# ============================================================
# INPUT NORMALIZATION
# ============================================================

def normalize_email_input(email_data):

    # If a string was supplied
    if isinstance(email_data, str):
        return {
            "from": "",
            "to": "",
            "subject": "",
            "body": email_data,
            "received": [],
            "spf": "",
            "dkim": "",
            "dmarc": "",
            "originating_ip": "",
        }

    # If dictionary was supplied
    if isinstance(email_data, dict):
        return {
            "from": str(email_data.get("from", "")),
            "to": str(email_data.get("to", "")),
            "subject": str(email_data.get("subject", "")),
            "body": str(email_data.get("body", "")),
            "received": email_data.get("received", []),
            "spf": str(email_data.get("spf", "")),
            "dkim": str(email_data.get("dkim", "")),
            "dmarc": str(email_data.get("dmarc", "")),
            "originating_ip": str(
                email_data.get("originating_ip", "")
            ),
        }

    raise TypeError(
        f"Unsupported email input type: {type(email_data).__name__}"
    )


# ============================================================
# PROMPT
# ============================================================

def build_prompt(email_data):

    email = normalize_email_input(email_data)

    return f"""
You are an email cybersecurity forensic analyst.

Analyze the following email for phishing, business email compromise,
spoofing, or legitimate communication.

Return ONLY valid JSON.

Required JSON structure:

{{
  "threat_score": 0,
  "classification": "legitimate",
  "psychological_tactic": "",
  "forensic_summary": "",
  "indicators_of_compromise": []
}}

Classification must be exactly one of:

legitimate
phishing
bec
spoofed

EMAIL:

From: {email["from"]}
To: {email["to"]}
Subject: {email["subject"]}

SPF: {email["spf"]}
DKIM: {email["dkim"]}
DMARC: {email["dmarc"]}

Originating IP: {email["originating_ip"]}

Received Headers:
{email["received"]}

Body:
{email["body"]}
"""


# ============================================================
# JSON EXTRACTION
# ============================================================

def extract_json(text):

    if not text:
        raise ValueError("AI returned an empty response")

    text = text.strip()

    # Remove markdown fences
    if "```json" in text:
        text = text.replace("```json", "")

    if "```" in text:
        text = text.replace("```", "")

    text = text.strip()

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1:
        raise ValueError("AI response did not contain JSON")

    return json.loads(text[start:end + 1])


# ============================================================
# RESULT NORMALIZATION
# ============================================================

def normalize_result(result, provider):

    if not isinstance(result, dict):
        raise ValueError("AI result is not a dictionary")

    classification = str(
        result.get("classification", "legitimate")
    ).lower()

    allowed = {
        "legitimate",
        "phishing",
        "bec",
        "spoofed",
    }

    if classification not in allowed:
        classification = "legitimate"

    try:
        threat_score = int(
            result.get("threat_score", 0)
        )
    except Exception:
        threat_score = 0

    threat_score = max(0, min(100, threat_score))

    iocs = result.get(
        "indicators_of_compromise",
        []
    )

    if not isinstance(iocs, list):
        iocs = [str(iocs)]

    return {
        "threat_score": threat_score,
        "classification": classification,
        "psychological_tactic": str(
            result.get("psychological_tactic", "")
        ),
        "forensic_summary": str(
            result.get("forensic_summary", "")
        ),
        "indicators_of_compromise": [
            str(x) for x in iocs
        ],
        "ai_provider": provider,
    }


# ============================================================
# GEMINI
# ============================================================

def call_gemini(email_data, api_key):

    from google import genai

    prompt = build_prompt(email_data)

    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
    )

    text = getattr(response, "text", None)

    if not text:
        raise ValueError("Gemini returned an empty response")

    result = extract_json(text)

    return normalize_result(result, "gemini")


# ============================================================
# GROQ
# ============================================================

def call_groq(email_data, api_key):

    from groq import Groq

    prompt = build_prompt(email_data)

    client = Groq(api_key=api_key)

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0,
    )

    text = response.choices[0].message.content

    result = extract_json(text)

    return normalize_result(result, "groq")


# ============================================================
# OPENROUTER
# ============================================================

def call_openrouter(email_data, api_key):

    prompt = build_prompt(email_data)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0,
    }

    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=AI_TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    text = data["choices"][0]["message"]["content"]

    result = extract_json(text)

    return normalize_result(
        result,
        "openrouter"
    )


# ============================================================
# OLLAMA
# ============================================================

def call_ollama(email_data):

    prompt = build_prompt(email_data)

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=AI_TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    text = data.get("response", "")

    result = extract_json(text)

    return normalize_result(
        result,
        "ollama"
    )


# ============================================================
# MAIN AI FUNCTION
# ============================================================

def analyze_with_ai(email_data):

    providers = []

    if PRIMARY_PROVIDER == "gemini":
        providers = ["gemini", "groq", "openrouter", "ollama"]

    elif PRIMARY_PROVIDER == "groq":
        providers = ["groq", "gemini", "openrouter", "ollama"]

    elif PRIMARY_PROVIDER == "openrouter":
        providers = ["openrouter", "gemini", "groq", "ollama"]

    elif PRIMARY_PROVIDER == "ollama":
        providers = ["ollama", "gemini", "groq", "openrouter"]

    else:
        providers = ["gemini", "groq", "openrouter", "ollama"]

    print("\n================ AI PROVIDER TEST ================")

    for provider in providers:

        try:

            if provider == "gemini":

                if not GEMINI_KEYS:
                    print("[GEMINI] ❌ No API key configured")
                    continue

                for index, key in enumerate(GEMINI_KEYS, start=1):

                    try:

                        print(
                            f"[GEMINI {index}] Testing..."
                        )

                        result = call_gemini(
                            email_data,
                            key
                        )

                        print(
                            f"[GEMINI {index}] ✅ WORKING"
                        )

                        print(
                            "AI selected: GEMINI"
                        )

                        return result

                    except Exception as error:

                        print(
                            f"[GEMINI {index}] ❌ FAILED: {error}"
                        )

            elif provider == "groq":

                if not GROQ_KEYS:
                    print("[GROQ] ❌ No API key configured")
                    continue

                for index, key in enumerate(GROQ_KEYS, start=1):

                    try:

                        print(
                            f"[GROQ {index}] Testing..."
                        )

                        result = call_groq(
                            email_data,
                            key
                        )

                        print(
                            f"[GROQ {index}] ✅ WORKING"
                        )

                        print(
                            "AI selected: GROQ"
                        )

                        return result

                    except Exception as error:

                        print(
                            f"[GROQ {index}] ❌ FAILED: {error}"
                        )

            elif provider == "openrouter":

                if not OPENROUTER_KEYS:
                    print(
                        "[OPENROUTER] ❌ No API key configured"
                    )
                    continue

                for index, key in enumerate(
                    OPENROUTER_KEYS,
                    start=1
                ):

                    try:

                        print(
                            f"[OPENROUTER {index}] Testing..."
                        )

                        result = call_openrouter(
                            email_data,
                            key
                        )

                        print(
                            f"[OPENROUTER {index}] ✅ WORKING"
                        )

                        print(
                            "AI selected: OPENROUTER"
                        )

                        return result

                    except Exception as error:

                        print(
                            f"[OPENROUTER {index}] ❌ FAILED: {error}"
                        )

            elif provider == "ollama":

                try:

                    print(
                        "[OLLAMA] Testing..."
                    )

                    result = call_ollama(
                        email_data
                    )

                    print(
                        "[OLLAMA] ✅ WORKING"
                    )

                    print(
                        "AI selected: OLLAMA"
                    )

                    return result

                except Exception as error:

                    print(
                        f"[OLLAMA] ❌ FAILED: {error}"
                    )

        except Exception as error:

            print(
                f"[{provider.upper()}] ❌ PROVIDER ERROR: {error}"
            )

        if not FALLBACK_ENABLED:
            break

    print(
        "=================================================="
    )

    print(
        "❌ ALL AI PROVIDERS FAILED"
    )

    print(
        "Using deterministic forensic engine."
    )

    return {
        "threat_score": 0,
        "classification": "legitimate",
        "psychological_tactic": "",
        "forensic_summary": (
            "AI analysis unavailable. "
            "Deterministic forensic analysis should be used."
        ),
        "indicators_of_compromise": [],
        "ai_provider": "none",
    }


# ============================================================
# COMPATIBILITY WITH MAIN.PY
# ============================================================

def analyze_email_with_ai(email_data):

    return analyze_with_ai(email_data)