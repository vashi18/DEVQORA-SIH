import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()


# ============================================================
# CONFIGURATION — LOADED FROM .ENV
# ============================================================

# ---------------- GEMINI ----------------

GEMINI_KEYS = [
    os.getenv("GEMINI_API_KEY"),
    os.getenv("GEMINI_API_KEY_2"),
    os.getenv("GEMINI_API_KEY_3"),
]

GEMINI_KEYS = [
    key for key in GEMINI_KEYS
    if key
]

GEMINI_MODEL = os.getenv("GEMINI_MODEL")


# ---------------- GROQ ----------------

GROQ_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_2"),
]

GROQ_KEYS = [
    key for key in GROQ_KEYS
    if key
]

GROQ_MODEL = os.getenv("GROQ_MODEL")


# ---------------- OPENROUTER ----------------

OPENROUTER_KEYS = [
    os.getenv("OPENROUTER_API_KEY"),
    os.getenv("OPENROUTER_API_KEY_2"),
]

OPENROUTER_KEYS = [
    key for key in OPENROUTER_KEYS
    if key
]

OPENROUTER_MODEL = os.getenv(
    "OPENROUTER_MODEL"
)


# ---------------- OLLAMA ----------------

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL"
)


# ---------------- GENERAL SETTINGS ----------------

AI_TIMEOUT = int(
    os.getenv(
        "AI_TIMEOUT",
        "30"
    )
)

PRIMARY_PROVIDER = os.getenv(
    "AI_PRIMARY_PROVIDER",
    "gemini"
).lower()

FALLBACK_ENABLED = (
    os.getenv(
        "AI_FALLBACK_ENABLED",
        "true"
    ).lower() == "true"
)


# ============================================================
# NORMALIZE EMAIL DATA
# ============================================================

def normalize_email_data(email_data):

    return {
        "from": email_data.get(
            "from",
            ""
        ),

        "to": email_data.get(
            "to",
            ""
        ),

        "subject": email_data.get(
            "subject",
            ""
        ),

        "date": email_data.get(
            "date",
            ""
        ),

        "body": email_data.get(
            "body",
            ""
        ),

        "received": email_data.get(
            "received",
            []
        ),

        "spf": email_data.get(
            "spf",
            ""
        ),

        "dkim": email_data.get(
            "dkim",
            ""
        ),

        "dmarc": email_data.get(
            "dmarc",
            ""
        ),

        "originating_ip": email_data.get(
            "originating_ip",
            ""
        ),

        "url_count": email_data.get(
            "url_count",
            0
        ),

        "suspicious_url_count": email_data.get(
            "suspicious_url_count",
            0
        ),

        "deterministic_threat_score":
            email_data.get(
                "deterministic_threat_score",
                0
            ),

        "deterministic_classification":
            email_data.get(
                "deterministic_classification",
                "unknown"
            ),

        "forensic_evidence":
            email_data.get(
                "forensic_evidence",
                []
            ),
    }


# ============================================================
# BUILD AI PROMPT
# ============================================================

def build_prompt(email_data):

    data = normalize_email_data(
        email_data
    )

    return f"""
You are an expert cybersecurity and email-forensics analyst.

Analyze the email below and determine whether it is:

1. legitimate
2. phishing
3. bec
4. spoofed

IMPORTANT RULES:

- Do not rely only on URLs.
- BEC emails may contain zero malicious URLs.
- Analyze SPF, DKIM and DMARC.
- Analyze sender identity and domain.
- Analyze Received headers.
- Analyze financial requests.
- Analyze urgency.
- Analyze authority manipulation.
- Analyze secrecy.
- Analyze credential theft.
- Analyze social engineering.
- Consider typosquatting and impersonation.
- Use the deterministic forensic evidence as supporting evidence.
- Return ONLY valid JSON.
- Do not return Markdown.
- threat_score must be between 0 and 100.

================ EMAIL ================

FROM:
{data["from"]}

TO:
{data["to"]}

SUBJECT:
{data["subject"]}

DATE:
{data["date"]}


================ AUTHENTICATION ================

SPF:
{data["spf"]}

DKIM:
{data["dkim"]}

DMARC:
{data["dmarc"]}


================ RECEIVED HEADERS ================

{json.dumps(
    data["received"],
    indent=2
)}


================ ORIGINATING IP ================

{data["originating_ip"]}


================ URL INFORMATION ================

Total URLs:
{data["url_count"]}

Suspicious URLs:
{data["suspicious_url_count"]}


================ DETERMINISTIC ANALYSIS ================

Threat Score:
{data["deterministic_threat_score"]}

Classification:
{data["deterministic_classification"]}


================ FORENSIC EVIDENCE ================

{json.dumps(
    data["forensic_evidence"],
    indent=2
)}


================ EMAIL BODY ================

{data["body"]}


================ REQUIRED OUTPUT ================

Return exactly this JSON structure:

{{
    "threat_score": 0,

    "classification": "legitimate",

    "psychological_tactic": "",

    "forensic_summary": "",

    "indicators_of_compromise": [],

    "reasons": []
}}

The reasons array must explain WHY the email was classified that way.

Include both:

Technical evidence:
- SPF
- DKIM
- DMARC
- IP
- URL/domain indicators

Behavioral evidence:
- urgency
- authority
- fear
- financial pressure
- secrecy
- credential theft
- social engineering
"""


# ============================================================
# EXTRACT JSON FROM AI RESPONSE
# ============================================================

def extract_json(text):

    if not text:
        raise ValueError(
            "AI returned an empty response."
        )

    text = text.strip()

    # Remove Markdown code blocks
    if text.startswith("```"):

        text = text.replace(
            "```json",
            ""
        )

        text = text.replace(
            "```",
            ""
        )

        text = text.strip()

    # Try normal JSON
    try:

        return json.loads(
            text
        )

    except json.JSONDecodeError:
        pass

    # Search for JSON object
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1:

        json_text = text[
            start:end + 1
        ]

        try:

            return json.loads(
                json_text
            )

        except json.JSONDecodeError:
            pass

    raise ValueError(
        "AI response does not contain valid JSON."
    )


# ============================================================
# NORMALIZE AI RESULT
# ============================================================

def normalize_ai_result(
    result,
    provider
):

    classification = str(
        result.get(
            "classification",
            "unknown"
        )
    ).lower().strip()

    allowed_classes = {
        "legitimate",
        "phishing",
        "bec",
        "spoofed"
    }

    if classification not in allowed_classes:

        classification = "unknown"

    try:

        threat_score = int(
            result.get(
                "threat_score",
                0
            )
        )

    except (
        ValueError,
        TypeError
    ):

        threat_score = 0

    threat_score = max(
        0,
        min(
            100,
            threat_score
        )
    )

    iocs = result.get(
        "indicators_of_compromise",
        []
    )

    if not isinstance(
        iocs,
        list
    ):

        iocs = [
            str(iocs)
        ]

    reasons = result.get(
        "reasons",
        []
    )

    if not isinstance(
        reasons,
        list
    ):

        reasons = [
            str(reasons)
        ]

    return {

        "threat_score":
            threat_score,

        "classification":
            classification,

        "psychological_tactic":
            str(
                result.get(
                    "psychological_tactic",
                    ""
                )
            ),

        "forensic_summary":
            str(
                result.get(
                    "forensic_summary",
                    ""
                )
            ),

        "indicators_of_compromise":
            iocs,

        "reasons":
            reasons,

        "ai_provider":
            provider,

        "ai_status":
            "success"
    }


# ============================================================
# GEMINI
# ============================================================

def call_gemini(
    api_key,
    prompt
):

    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=api_key
    )

    response = client.models.generate_content(

        model=GEMINI_MODEL,

        contents=prompt,

        config=types.GenerateContentConfig(

            temperature=0,

            max_output_tokens=1200
        )
    )

    text = getattr(
        response,
        "text",
        None
    )

    if not text:

        raise ValueError(
            "Gemini returned an empty response."
        )

    result = extract_json(
        text
    )

    return normalize_ai_result(
        result,
        "google_ai_studio"
    )


# ============================================================
# GROQ
# ============================================================

def call_groq(
    api_key,
    prompt
):

    url = (
        "https://api.groq.com/openai/v1/"
        "chat/completions"
    )

    headers = {

        "Authorization":
            f"Bearer {api_key}",

        "Content-Type":
            "application/json"
    }

    payload = {

        "model":
            GROQ_MODEL,

        "messages": [

            {
                "role":
                    "system",

                "content":
                    "You are an expert "
                    "cybersecurity "
                    "email-forensics "
                    "analyst. Return "
                    "only valid JSON."
            },

            {
                "role":
                    "user",

                "content":
                    prompt
            }
        ],

        "temperature":
            0,

        "max_tokens":
            1200
    }

    response = requests.post(

        url,

        headers=headers,

        json=payload,

        timeout=AI_TIMEOUT
    )

    response.raise_for_status()

    data = response.json()

    text = (
        data["choices"][0]
        ["message"]["content"]
    )

    result = extract_json(
        text
    )

    return normalize_ai_result(
        result,
        "groq"
    )


# ============================================================
# OPENROUTER
# ============================================================

def call_openrouter(
    api_key,
    prompt
):

    url = (
        "https://openrouter.ai/api/v1/"
        "chat/completions"
    )

    headers = {

        "Authorization":
            f"Bearer {api_key}",

        "Content-Type":
            "application/json"
    }

    payload = {

        "model":
            OPENROUTER_MODEL,

        "messages": [

            {
                "role":
                    "system",

                "content":
                    "You are an expert "
                    "cybersecurity "
                    "email-forensics "
                    "analyst."
            },

            {
                "role":
                    "user",

                "content":
                    prompt
            }
        ],

        "temperature":
            0,

        "max_tokens":
            1200
    }

    response = requests.post(

        url,

        headers=headers,

        json=payload,

        timeout=AI_TIMEOUT
    )

    response.raise_for_status()

    data = response.json()

    text = (
        data["choices"][0]
        ["message"]["content"]
    )

    result = extract_json(
        text
    )

    return normalize_ai_result(
        result,
        "openrouter"
    )


# ============================================================
# OLLAMA
# ============================================================

def call_ollama(
    prompt
):

    url = (
        "http://localhost:11434/api/generate"
    )

    payload = {

        "model":
            OLLAMA_MODEL,

        "prompt":
            prompt,

        "stream":
            False,

        "format":
            "json",

        "options": {

            "temperature":
                0
        }
    }

    response = requests.post(

        url,

        json=payload,

        timeout=AI_TIMEOUT
    )

    response.raise_for_status()

    data = response.json()

    text = data.get(
        "response",
        ""
    )

    result = extract_json(
        text
    )

    return normalize_ai_result(
        result,
        "ollama"
    )


# ============================================================
# PROVIDER ORDER
# ============================================================

def get_provider_order():

    providers = [

        "gemini",

        "groq",

        "openrouter",

        "ollama"
    ]

    if PRIMARY_PROVIDER in providers:

        providers.remove(
            PRIMARY_PROVIDER
        )

        providers.insert(
            0,
            PRIMARY_PROVIDER
        )

    return providers


# ============================================================
# MAIN AI FUNCTION
# ============================================================

def analyze_with_ai(
    email_data
):

    prompt = build_prompt(
        email_data
    )

    attempts = []

    providers = get_provider_order()

    if not FALLBACK_ENABLED:

        providers = [
            PRIMARY_PROVIDER
        ]

    # ========================================================
    # TRY PROVIDERS
    # ========================================================

    for provider in providers:

        # ----------------------------------------------------
        # GEMINI
        # ----------------------------------------------------

        if provider == "gemini":

            if not GEMINI_KEYS:

                attempts.append({

                    "provider":
                        "google_ai_studio",

                    "status":
                        "not_configured"
                })

                continue

            for index, key in enumerate(
                GEMINI_KEYS,
                start=1
            ):

                try:

                    print(
                        f"[GEMINI {index}] Testing..."
                    )

                    result = call_gemini(
                        key,
                        prompt
                    )

                    print(
                        f"[GEMINI {index}] "
                        f"WORKING"
                    )

                    result[
                        "ai_attempts"
                    ] = attempts

                    return result

                except Exception as error:

                    print(
                        f"[GEMINI {index}] "
                        f"FAILED: {error}"
                    )

                    attempts.append({

                        "provider":
                            "google_ai_studio",

                        "key_number":
                            index,

                        "status":
                            "failed",

                        "error":
                            str(error)
                    })


        # ----------------------------------------------------
        # GROQ
        # ----------------------------------------------------

        elif provider == "groq":

            if not GROQ_KEYS:

                attempts.append({

                    "provider":
                        "groq",

                    "status":
                        "not_configured"
                })

                continue

            for index, key in enumerate(
                GROQ_KEYS,
                start=1
            ):

                try:

                    print(
                        f"[GROQ {index}] Testing..."
                    )

                    result = call_groq(
                        key,
                        prompt
                    )

                    print(
                        f"[GROQ {index}] "
                        f"WORKING"
                    )

                    result[
                        "ai_attempts"
                    ] = attempts

                    return result

                except Exception as error:

                    print(
                        f"[GROQ {index}] "
                        f"FAILED: {error}"
                    )

                    attempts.append({

                        "provider":
                            "groq",

                        "key_number":
                            index,

                        "status":
                            "failed",

                        "error":
                            str(error)
                    })


        # ----------------------------------------------------
        # OPENROUTER
        # ----------------------------------------------------

        elif provider == "openrouter":

            if not OPENROUTER_KEYS:

                attempts.append({

                    "provider":
                        "openrouter",

                    "status":
                        "not_configured"
                })

                continue

            for index, key in enumerate(
                OPENROUTER_KEYS,
                start=1
            ):

                try:

                    print(
                        f"[OPENROUTER {index}] "
                        f"Testing..."
                    )

                    result = call_openrouter(
                        key,
                        prompt
                    )

                    print(
                        f"[OPENROUTER {index}] "
                        f"WORKING"
                    )

                    result[
                        "ai_attempts"
                    ] = attempts

                    return result

                except Exception as error:

                    print(
                        f"[OPENROUTER {index}] "
                        f"FAILED: {error}"
                    )

                    attempts.append({

                        "provider":
                            "openrouter",

                        "key_number":
                            index,

                        "status":
                            "failed",

                        "error":
                            str(error)
                    })


        # ----------------------------------------------------
        # OLLAMA
        # ----------------------------------------------------

        elif provider == "ollama":

            try:

                print(
                    "[OLLAMA] Testing..."
                )

                result = call_ollama(
                    prompt
                )

                print(
                    "[OLLAMA] WORKING"
                )

                result[
                    "ai_attempts"
                ] = attempts

                return result

            except Exception as error:

                print(
                    f"[OLLAMA] FAILED: {error}"
                )

                attempts.append({

                    "provider":
                        "ollama",

                    "status":
                        "failed",

                    "error":
                        str(error)
                })


    # ========================================================
    # ALL AI PROVIDERS FAILED
    # ========================================================

    deterministic_score = int(
        email_data.get(
            "deterministic_threat_score",
            0
        )
    )

    deterministic_classification = (
        email_data.get(
            "deterministic_classification",
            "unknown"
        )
    )

    return {

        "threat_score":
            max(
                0,
                min(
                    100,
                    deterministic_score
                )
            ),

        "classification":
            deterministic_classification,

        "psychological_tactic":
            "",

        "forensic_summary":
            "AI providers failed. "
            "Deterministic forensic "
            "analysis was used.",

        "indicators_of_compromise":
            [],

        "reasons":
            email_data.get(
                "forensic_evidence",
                []
            ),

        "ai_provider":
            "none",

        "ai_status":
            "failed",

        "ai_attempts":
            attempts
    }


# ============================================================
# FUNCTION USED BY MAIN.PY
# ============================================================

def analyze_email_with_ai(
    email_data
):

    return analyze_with_ai(
        email_data
    )