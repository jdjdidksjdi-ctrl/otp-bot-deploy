#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zenex Master  —  OTP API (Web Service Version)
=================================================
Features:
  - Auto-login + token refresh in background
  - OTP API poll every 5 seconds
  - Flask Web API to fetch OTPs in realtime
  - API Key authentication
"""

import io, sys, re, time, json, threading, base64, os
from pathlib import Path
from datetime import datetime
import requests
from flask import Flask, request, jsonify

# ── UTF-8 ─────────────────────────────────────────────────────
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════
EMAIL    = "rakibkumar151@gmail.com"
PASSWORD = "rakibkumar151@gmail.com"

# API_KEY is used to secure your endpoint
API_KEY  = os.environ.get("API_KEY", "zenex_api_secret_123")

LOGIN_URL   = "https://zenexnetwork.com/api/login"
OTP_API_URL = "https://zenexnetwork.com/api/check-otp"

POLL_INTERVAL      = 5
TOKEN_REFRESH_SEC  = 5 * 3600
RETRY_SLEEP        = 10
LOGIN_RETRY_SLEEP  = 30

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36"
)

BASE           = Path(__file__).parent
FB_OTP_FILE    = BASE / "fb_otp.txt"
INSTA_OTP_FILE = BASE / "insta_otp.txt"

# ── State ─────────────────────────────────────────────────────
_lock        = threading.Lock()
_token       = ""
_token_exp   = 0
_last_renew  = 0
_seen_nids   = set()
_seen_pairs  = set()
_total_saved = 0

def get_time_ago(time_str):
    if time_str == "Unknown":
        return "Unknown"
    try:
        past = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        diff = datetime.now() - past
        seconds = diff.total_seconds()
        
        if seconds < 10:
            return "just now"
        elif seconds < 60:
            return f"{int(seconds)} sec ago"
        elif seconds < 3600:
            return f"{int(seconds // 60)} min ago"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} h ago"
        elif seconds < 2592000:
            return f"{int(seconds // 86400)} day ago"
        else:
            return f"{int(seconds // 2592000)} m ago"
    except Exception:
        return "Unknown"


# ══════════════════════════════════════════════════════════════
#  FLASK APP SETUP
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)

def require_api_key(func):
    def wrapper(*args, **kwargs):
        provided_key = request.args.get("api_key") or request.headers.get("x-api-key")
        if not provided_key or provided_key != API_KEY:
            return jsonify({"error": "Unauthorized. Invalid or missing API key."}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route("/")
def index():
    return jsonify({
        "status": "running",
        "message": "Zenex OTP API is active.",
        "usage": "/api/otps?api_key=YOUR_KEY"
    })

@app.route("/api/otps", methods=["GET"])
@require_api_key
def get_otps():
    limit_str = request.args.get("list") or request.args.get("limit")
    try:
        limit = int(limit_str) if limit_str else 5
    except ValueError:
        limit = 5

    platform = request.args.get("platform", default="all").lower()
    
    digits_str = request.args.get("digits")
    digits_filter = int(digits_str) if digits_str and digits_str.isdigit() else None
    
    fb_data = []
    if platform in ("all", "fb") and FB_OTP_FILE.exists():
        lines = FB_OTP_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        valid_fb = []
        for ln in lines:
            parts = ln.split("|")
            if len(parts) >= 2:
                if digits_filter is None or len(parts[1]) == digits_filter:
                    valid_fb.append(parts)
        for parts in valid_fb[-limit:]:
            if len(parts) >= 3:
                time_ago = get_time_ago(parts[2])
                fb_data.append({"number": parts[0], "otp": parts[1], "time": parts[2], "time_ago": time_ago})
            else:
                fb_data.append({"number": parts[0], "otp": parts[1], "time": "Unknown", "time_ago": "Unknown"})
                
    insta_data = []
    if platform in ("all", "insta") and INSTA_OTP_FILE.exists():
        lines = INSTA_OTP_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        valid_insta = []
        for ln in lines:
            parts = ln.split("|")
            if len(parts) >= 2:
                if digits_filter is None or len(parts[1]) == digits_filter:
                    valid_insta.append(parts)
        for parts in valid_insta[-limit:]:
            if len(parts) >= 3:
                time_ago = get_time_ago(parts[2])
                insta_data.append({"number": parts[0], "otp": parts[1], "time": parts[2], "time_ago": time_ago})
            else:
                insta_data.append({"number": parts[0], "otp": parts[1], "time": "Unknown", "time_ago": "Unknown"})

    fb_data.reverse()
    insta_data.reverse()

    total = 0
    if FB_OTP_FILE.exists():
        with open(FB_OTP_FILE, "r", encoding="utf-8") as f:
            total += sum(1 for _ in f)
    if INSTA_OTP_FILE.exists():
        with open(INSTA_OTP_FILE, "r", encoding="utf-8") as f:
            total += sum(1 for _ in f)

    data = {}
    if platform == "fb":
        data = {"fb": fb_data}
    elif platform == "insta":
        data = {"insta": insta_data}
    else:
        data = {"fb": fb_data, "insta": insta_data}
        
    return jsonify({
        "success": True,
        "total_saved": total,
        "data": data,
        "timestamp": datetime.now().isoformat()
    })


# ══════════════════════════════════════════════════════════════
#  LOGGING & HELPERS
# ══════════════════════════════════════════════════════════════
def log(msg: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {msg}"
    print(line, flush=True)

def now_ms() -> int:
    return int(time.time() * 1000)

_INSTA_HASHES = {"GdDGcwrWHVm", "SIYRxKrru1t", "#ig"}

def extract_otp_code(raw_otp: str) -> str:
    raw = raw_otp.strip()
    m = re.search(r'\bFB-?(\d{4,8})\b', raw, re.IGNORECASE)
    if m:
        return m.group(1)
    if re.fullmatch(r'\d{4,10}', raw):
        return raw
    three_digit = re.findall(r'\b(\d{3})\b', raw)
    if len(three_digit) >= 2:
        stripped = raw.lstrip('<#> ')
        if stripped.startswith(three_digit[0]):
            return three_digit[0] + three_digit[1]
    numbers = re.findall(r'\b(\d{4,10})\b', raw)
    if numbers:
        return numbers[0]
    numbers = re.findall(r'\b(\d{3,})\b', raw)
    if numbers:
        return numbers[0]
    return raw

def classify_platform(number: str, otp_text: str) -> str:
    text_lower = otp_text.lower()
    if "instagram" in text_lower:
        return "insta"
    for h in _INSTA_HASHES:
        if h in otp_text:
            return "insta"
    if "#ig" in otp_text:
        return "insta"
    
    fb_keywords = [
        "facebook", "fb-", "fb ",
        "kode facebook", "code facebook",
        "votre code", "est le code",
        "kode atur ulang", "facebook code",
        "facebook password", "facebook confirmation",
        "facebook-",
    ]
    for kw in fb_keywords:
        if kw in text_lower:
            return "fb"
    return "others"

def decode_exp(token: str) -> int:
    try:
        parts = token.split(".")
        pad   = parts[1] + "=" * (-len(parts[1]) % 4)
        data  = json.loads(base64.urlsafe_b64decode(pad))
        return int(data.get("exp", 0))
    except Exception:
        return 0

def ensure_files() -> None:
    for f in [FB_OTP_FILE, INSTA_OTP_FILE]:
        if not f.exists():
            f.touch()

def load_existing() -> None:
    global _seen_pairs, _total_saved
    ensure_files()
    total = 0
    for src_file in [FB_OTP_FILE, INSTA_OTP_FILE]:
        if src_file.exists():
            for ln in src_file.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if ln and "|" in ln:
                    parts = ln.split("|")
                    if len(parts) >= 2:
                        _seen_pairs.add(f"{parts[0]}|{parts[1]}")
                        total += 1
    _total_saved = total
    log(f"[INIT] Loaded {total} pairs from existing files")

# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════
def do_login(session: requests.Session) -> bool:
    global _token, _token_exp, _last_renew
    headers = {
        "content-type":    "application/json",
        "user-agent":      USER_AGENT,
        "origin":          "https://zenexnetwork.com",
        "referer":         "https://zenexnetwork.com/login",
    }
    try:
        r = session.post(
            LOGIN_URL,
            json={"emailOrPhone": EMAIL, "password": PASSWORD},
            headers=headers,
            timeout=20
        )
        if r.status_code == 200:
            sc    = r.headers.get("set-cookie", "")
            match = re.search(r"zenex_token=([^;]+)", sc)
            token = match.group(1) if match else r.cookies.get("zenex_token", "")
            if not token:
                log("[LOGIN] 200 OK but no token")
                return False
            exp = decode_exp(token)
            with _lock:
                _token      = token
                _token_exp  = exp
                _last_renew = int(time.time())
            log("[LOGIN] SUCCESS")
            return True
        else:
            log(f"[LOGIN] FAILED {r.status_code}")
            return False
    except Exception as e:
        log(f"[LOGIN] Exception: {e}")
        return False

def need_refresh() -> bool:
    with _lock:
        now = int(time.time())
        if not _token:
            return True
        if _token_exp and (_token_exp - now) < 1800:
            return True
        if (now - _last_renew) >= TOKEN_REFRESH_SEC:
            return True
    return False

def otp_headers() -> dict:
    with _lock:
        tok = _token
    return {
        "cookie":     f"zenex_token={tok}",
        "referer":    "https://zenexnetwork.com/",
        "user-agent": USER_AGENT,
    }

# ══════════════════════════════════════════════════════════════
#  OTP POLL + SAVE
# ══════════════════════════════════════════════════════════════
def poll_otp(session: requests.Session) -> dict:
    ts  = now_ms()
    url = f"{OTP_API_URL}?t={ts}"
    try:
        r = session.get(url, headers=otp_headers(), timeout=15)
        if r.status_code == 200:
            try:
                return {"status": 200, "response": r.json()}
            except:
                pass
        return {"status": r.status_code, "response": {}}
    except Exception as e:
        return {"status": "ERROR", "response": {}}

def save_otp_pairs(record: dict) -> None:
    global _total_saved
    resp = record.get("response", {})
    if not isinstance(resp, dict):
        return

    for item in resp.get("otps", []):
        nid      = str(item.get("nid",    "")).strip()
        number   = str(item.get("number", "")).strip()
        raw_otp  = str(item.get("otp",    "")).strip()
        if not number or not raw_otp:
            continue

        clean_otp = extract_otp_code(raw_otp)
        platform  = classify_platform(number, raw_otp)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_key = f"{number}|{clean_otp}"
        entry_line = f"{number}|{clean_otp}|{current_time}"

        with _lock:
            if nid and nid in _seen_nids:
                continue
            if entry_key in _seen_pairs:
                continue

            target_file = None
            if platform == "fb":
                target_file = FB_OTP_FILE
            elif platform == "insta":
                target_file = INSTA_OTP_FILE

            if target_file:
                try:
                    with open(target_file, "a", encoding="utf-8") as f:
                        f.write(entry_line + "\n")
                        f.flush()
                except Exception as fe:
                    log(f"[SAVE ERR] Write to {target_file.name}: {fe}")
                    continue

                _total_saved += 1
                log(f"[{platform.upper()}] {entry_key}")

            _seen_pairs.add(entry_key)
            if nid:
                _seen_nids.add(nid)

# ══════════════════════════════════════════════════════════════
#  BACKGROUND LOOP
# ══════════════════════════════════════════════════════════════
def background_worker():
    log("[BOOT] Background worker starting...")
    load_existing()
    session = requests.Session()
    req_count = 0

    log("[BOOT] Logging in...")
    while True:
        if do_login(session):
            break
        log(f"[BOOT] Retry in {LOGIN_RETRY_SLEEP}s...")
        time.sleep(LOGIN_RETRY_SLEEP)

    log("[BOOT] Ready — collecting OTPs...")

    while True:
        if need_refresh():
            log("[TOKEN] Refreshing...")
            if not do_login(session):
                time.sleep(LOGIN_RETRY_SLEEP)
                continue

        try:
            rec = poll_otp(session)
            req_count += 1
            status = rec["status"]

            if status == 200:
                save_otp_pairs(rec)
            elif status == 401:
                log("[OTP] 401 — forcing token refresh")
                with _lock:
                    _token = ""
            elif str(status) == "ERROR":
                time.sleep(RETRY_SLEEP)
                continue

        except Exception as e:
            log(f"[LOOP ERR] {e}")
            time.sleep(RETRY_SLEEP)
            continue

        time.sleep(POLL_INTERVAL)

# ══════════════════════════════════════════════════════════════
#  ENTRY
# ══════════════════════════════════════════════════════════════
worker_thread = threading.Thread(target=background_worker, daemon=True)
worker_thread.start()

if __name__ == "__main__":
    # Run Flask App locally
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
