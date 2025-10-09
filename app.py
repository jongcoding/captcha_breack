import os
import hmac
import hashlib
import time
import secrets
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask import render_template_string
# ===================== 환경 변수 =====================
from dotenv import load_dotenv
load_dotenv()

GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
GEETEST_VALIDATE_URL = "https://gcaptcha4.geetest.com/validate"

# ★ Enterprise
RECAPTCHA_ENTERPRISE_API_KEY    = os.getenv("RECAPTCHA_ENTERPRISE_API_KEY", "")
RECAPTCHA_ENTERPRISE_PROJECT_ID = os.getenv("RECAPTCHA_ENTERPRISE_PROJECT_ID", "")

FLAG = os.getenv("FLAG", "FLAG{c0de_only_g4te_p4ssed}")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

# 단계 제한시간(ms)
MAX_RESPONSE_TIME_MS = int(os.getenv("MAX_RESPONSE_TIME_MS", "60000"))

# 자동화 게이트 파라미터
SIG_BUCKET_MS    = int(os.getenv("SIG_BUCKET_MS", "120"))
PULSE_MAX_AGE_MS = int(os.getenv("PULSE_MAX_AGE_MS", "320"))
POW_BITS         = int(os.getenv("POW_BITS", "18"))
TICKET_TTL_MS    = int(os.getenv("TICKET_TTL_MS", "10000"))
GEETEST_MAX_TIME_MS = int(os.getenv("GEETEST_MAX_TIME_MS", "10000"))  # GeeTest 풀이 최대 시간 (2captcha 방지)
FX_HDR_NAME      = os.getenv("FX_HDR_NAME", "X-Fx-Sig")
BLOCK_BROWSER    = os.getenv("BLOCK_BROWSER", "1") == "1"

# 개발 편의(운영=0)  ← 요청대로 그대로 둔다
DEV_DISABLE_SIG = os.getenv("DEV_DISABLE_SIG", "0") == "1"

# reCAPTCHA 키 (v2 + v3/Enterprise)
RECAPTCHA_V2_SITE_KEY   = os.getenv("RECAPTCHA_V2_SITE_KEY", "")
RECAPTCHA_V2_SECRET_KEY = os.getenv("RECAPTCHA_V2_SECRET_KEY", "")
RECAPTCHA_V3_SITE_KEY   = os.getenv("RECAPTCHA_V3_SITE_KEY", "")   # Enterprise에도 siteKey로 사용
RECAPTCHA_V3_SECRET_KEY = os.getenv("RECAPTCHA_V3_SECRET_KEY", "") # 레거시 폴백용

# v3 점수 임계값
V3_HUMAN_MIN    = float(os.getenv("V3_HUMAN_MIN", "0.95"))  # 0.95 이상만 사람으로 간주하여 차단
V3_ACCEPT_MAX   = float(os.getenv("V3_ACCEPT_MAX","0.90"))  # 0.90 이하는 봇으로 허용 (0.9도 포함)
V3_MID_TREAT_AS = os.getenv("V3_MID_TREAT_AS", "reject")    # 중간 점수는 거부

EXPECTED_HOSTNAME   = os.getenv("EXPECTED_HOSTNAME")
GEETEST_CAPTCHA_ID  = os.getenv("GEETEST_CAPTCHA_ID", "")
GEETEST_CAPTCHA_KEY = os.getenv("GEETEST_CAPTCHA_KEY", "")

# JA3/JA4 블랙리스트(옵션)
JA3_BADLIST = set(x.strip() for x in os.getenv("JA3_BADLIST", "").split(",") if x.strip())
JA4_BADLIST = set(x.strip() for x in os.getenv("JA4_BADLIST", "").split(",") if x.strip())

API_BROWSER_ALLOWLIST = {
    "/api/step2/begin",
    "/api/step2/verify-slide",
    "/api/step2/status",
}

def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    sessions = {}  # 메모리 세션(CTF 용)

    # ============== 유틸 ==============
    def now_ms() -> int:
        return int(time.time() * 1000)

    def sha256_body() -> str:
        b = request.get_data(cache=True) or b""
        return hashlib.sha256(b).hexdigest()

    def lzbits(bb: bytes) -> int:
        n = 0
        for x in bb:
            if x == 0:
                n += 8
                continue
            for i in range(7, -1, -1):
                if (x >> i) & 1:
                    return n + (7 - i)
            return n
        return n

    def client_ip() -> str:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or ""

    BROWSER_HDRS = (
       "Sec-Fetch-Mode","Sec-Fetch-Site","Sec-Fetch-Dest",
        "Sec-CH-UA","Sec-CH-UA-Mobile","Sec-CH-UA-Platform",
        "Upgrade-Insecure-Requests",
    )
    @app.before_request
    def block_browser_on_api():
        if not BLOCK_BROWSER:
            return
        if request.path.startswith("/api/") and request.path not in API_BROWSER_ALLOWLIST:
            for h in BROWSER_HDRS:
                if request.headers.get(h):
                    return jsonify({"ok": False, "reason": "browser_blocked"}), 403

    def sig_for(key_hex: str, bucket: int, host_override: str = None) -> str:
        key = bytes.fromhex(key_hex)
        host = host_override or request.host
        msg = "\n".join([
            request.method.upper(),
            host,
            request.path,
            sha256_body(),
            str(bucket),
        ]).encode()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def _host_variants(h: str):
        if not h:
            return []
        hosts = {h}
        
        if ":" in h and not h.startswith("["):  
            name, port = h.rsplit(":", 1)
            if name == "localhost":
                hosts.add(f"127.0.0.1:{port}")
            elif name == "127.0.0.1":
                hosts.add(f"localhost:{port}")
        else:
            if h == "localhost":
                hosts.add("127.0.0.1")
            elif h == "127.0.0.1":
                hosts.add("localhost")
        return list(hosts)

    def _candidate_hosts(stored_host: str = None):
        cand = set()
        cand.update(_host_variants(stored_host or ""))
        cand.update(_host_variants(request.host))
        cand.update(_host_variants(request.headers.get("Host", "")))
        cand.update(_host_variants(request.headers.get("X-Forwarded-Host", "")))
        return [c for c in cand if c]

    def require_sig_and_pulse():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        st = sessions[sid].get("fx")
        if not st:
            return jsonify({"ok": False, "reason": "no_handshake"}), 403

        sig_hdr = request.headers.get(FX_HDR_NAME, "")
        sig_ck1 = request.cookies.get("fxsig", "")
        sig_ck2 = request.cookies.get("fx_sig", "")
        sig_q1  = request.args.get("_fx", "")
        sig_q2  = request.args.get("fx", "")
        sig = sig_hdr or sig_ck1 or sig_ck2 or sig_q1 or sig_q2
        sig_present = bool(sig)

        want_debug = request.args.get("__sigdebug") == "1"

        if not DEV_DISABLE_SIG:
            bkt_now = now_ms() // SIG_BUCKET_MS
            buckets = (bkt_now - 1, bkt_now, bkt_now + 1)

            
            def _host_variants(h: str):
                if not h: return []
                s = {h}
                if ":" in h and not h.startswith("["):
                    name, port = h.rsplit(":", 1)
                    if name == "localhost":   s.add(f"127.0.0.1:{port}")
                    if name == "127.0.0.1":   s.add(f"localhost:{port}")
                else:
                    if h == "localhost":  s.add("127.0.0.1")
                    if h == "127.0.0.1":  s.add("localhost")
                return list(s)

            host_base = (st.get("host") or request.host or request.headers.get("Host", ""))
            candidates = set()
            for h in (host_base, request.host, request.headers.get("Host", ""), request.headers.get("X-Forwarded-Host", "")):
                candidates.update(_host_variants(h or ""))

            ok = False
            if sig_present:
                for h in candidates or [request.host]:
                    for b in buckets:
                        msg = "\n".join([
                            request.method.upper(),
                            h,
                            request.path,                         # 쿼리는 서명에 포함 X
                            hashlib.sha256((request.get_data(cache=True) or b"")).hexdigest(),
                            str(b),
                        ]).encode()
                        expect = hmac.new(bytes.fromhex(st["key"]), msg, hashlib.sha256).hexdigest()
                        if hmac.compare_digest(sig, expect):
                            ok = True
                            break
                    if ok:
                        break

            if not ok:
                if want_debug:
                    return jsonify({
                        "ok": False,
                        "reason": "bad_signature",
                        "debug": {
                            "method": request.method.upper(),
                            "path": request.path,
                            "request_host": request.host,
                            "sig_bucket_ms": SIG_BUCKET_MS,
                            "buckets": list(buckets),
                            "candidates": sorted(candidates),
                            "body_sha256": hashlib.sha256((request.get_data(cache=True) or b"")).hexdigest(),
                            "sig_present": sig_present,
                            "sig_prefix": (sig[:16] if sig_present else None),
                        }
                    }), 403
                return jsonify({"ok": False, "reason": "bad_signature"}), 403
        else:
            print(f"[DEBUG] Signature check bypassed (DEV_DISABLE_SIG=1) for {sid}")

        
        if now_ms() - sessions[sid].get("last_pulse_ms", 0) > PULSE_MAX_AGE_MS:
            return jsonify({"ok": False, "reason": "pulse_required"}), 429
        return None  

    def start_step(sess: dict, step_key: str):
        now = time.monotonic()
        sess[f"{step_key}_started"] = now
        sess[f"{step_key}_expire"]  = now + MAX_RESPONSE_TIME_MS / 1000.0
        sess[f"{step_key}_count"]   = sess.get(f"{step_key}_count", 0) + 1

    def check_deadline_or_kill(step_key: str, reason_prefix: str):
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return False, (jsonify({"ok": False, "reason": "session_expired"}), 401)
        sess = sessions[sid]
        if sess.get(f"{step_key}_captcha_done"):
            return True, None
        now = time.monotonic()
        if now > sess.get(f"{step_key}_expire", 0.0):
            kill_session(reason=f"{reason_prefix}_timeout")
            return False, (jsonify({"ok": False, "reason": "timeout", "killed": True}), 400)
        return True, None

    def remaining_ms(step_key: str) -> int:
        sid = session.get("sid")
        sess = sessions[sid]
        return max(0, int((sess[f"{step_key}_expire"] - time.monotonic()) * 1000))

    def kill_session(reason="unknown"):
        sid = session.get("sid")
        if sid and sid in sessions:
            print(f"[KILL] {sid} : {reason}")
            del sessions[sid]
        session.clear()
        return reason

    def _hostname_ok(payload: dict) -> bool:
        if not EXPECTED_HOSTNAME:
            return True
        allowed = [h.strip() for h in str(EXPECTED_HOSTNAME).split(",") if h.strip()]
        return (payload.get("hostname") in allowed)

    def verify_recaptcha_v2(token: str, remote_ip: str):
        if not token:
            return False, {"error": "missing-token"}
        data = {
            "secret": RECAPTCHA_V2_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip,
        }
        try:
            resp = requests.post(GOOGLE_VERIFY_URL, data=data, timeout=5)
            payload = resp.json()
        except Exception as e:
            return False, {"error": "recaptcha_request_error", "detail": str(e)}
        ok = bool(payload.get("success")) and _hostname_ok(payload)
        print("[RECAPTCHA v2]", payload)
        return ok, payload

    def verify_recaptcha_v3(token: str, remote_ip: str, expected_action: str = None):
    
        if not token:
            return False, {"error": "v3_token_required"}

        if RECAPTCHA_ENTERPRISE_API_KEY and RECAPTCHA_ENTERPRISE_PROJECT_ID and RECAPTCHA_V3_SITE_KEY:
            url = (
                f"https://recaptchaenterprise.googleapis.com/v1/"
                f"projects/{RECAPTCHA_ENTERPRISE_PROJECT_ID}/assessments"
                f"?key={RECAPTCHA_ENTERPRISE_API_KEY}"
            )
            event = {
                "token": token,
                "siteKey": RECAPTCHA_V3_SITE_KEY,
                "expectedAction": expected_action or "",
                "userAgent": request.headers.get("User-Agent", ""),
                "userIpAddress": client_ip(),
            }
            
            ja3 = request.headers.get("X-JA3")
            ja4 = request.headers.get("X-JA4")
            if ja3:
                event["ja3"] = ja3
            if ja4:
                event["ja4"] = ja4

            try:
                r = requests.post(url, json={"event": event}, timeout=5)
                data = r.json()
                print("[RECAPTCHA v3 Enterprise]", data)
            except Exception as e:
                return False, {"error": "enterprise_request_failed", "detail": str(e)}

            token_props = data.get("tokenProperties", {}) or {}
            if not token_props.get("valid"):
                return False, {"error": "invalid_token", "reason": token_props.get("invalidReason")}

            action = token_props.get("action")
            if expected_action and action != expected_action:
                return False, {"error": "wrong-action", "action": action}

            ra = data.get("riskAnalysis", {}) or {}
            score = float(ra.get("score", 0.0))
            reasons = ra.get("reasons", [])

            if score >= V3_HUMAN_MIN:
                return False, {"error": "human_behavior_detected", "score": score, "reasons": reasons}
            if score <= V3_ACCEPT_MAX:
                return True, {"score": score, "reasons": reasons}

            if V3_MID_TREAT_AS.lower() == "accept":
                return True, {"score": score, "reasons": reasons, "note": "mid-accepted"}
            else:
                return False, {"error": "score_mid_zone", "score": score, "reasons": reasons}

        data = {
            "secret": RECAPTCHA_V3_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip,
        }
        try:
            resp = requests.post(GOOGLE_VERIFY_URL, data=data, timeout=5)
            payload = resp.json()
            print("[RECAPTCHA v3 Legacy]", payload)
        except Exception as e:
            return False, {"error": "legacy_request_failed", "detail": str(e)}

        success = bool(payload.get("success"))
        score = float(payload.get("score", 0.0))
        action = payload.get("action")
        host_ok = _hostname_ok(payload)

        if expected_action and action != expected_action:
            return False, {"error": "wrong-action", "action": action, "score": score}
        if not (success and host_ok):
            return False, {"error": "verification_failed", "success": success, "hostname_ok": host_ok}

        if score >= V3_HUMAN_MIN:
            return False, {"error": "human_behavior_detected", "score": score}
        if score <= V3_ACCEPT_MAX:
            return True, {"score": score}
        if V3_MID_TREAT_AS.lower() == "accept":
            return True, {"score": score, "note": "mid-accepted"}
        return False, {"error": "score_mid_zone", "score": score}

    def verify_geetest(lot_number, captcha_output, pass_token, gen_time):
        if not all([lot_number, captcha_output, pass_token, gen_time]):
            return False, {"error": "missing_params"}
        sign_token = hmac.new(
            GEETEST_CAPTCHA_KEY.encode("utf-8"),
            lot_number.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        payload = {
            "lot_number": lot_number,
            "captcha_output": captcha_output,
            "pass_token": pass_token,
            "gen_time": gen_time,
            "sign_token": sign_token,
        }
        url = f"{GEETEST_VALIDATE_URL}?captcha_id={GEETEST_CAPTCHA_ID}"
        try:
            r = requests.post(url, data=payload, timeout=5)
            r.raise_for_status()
            data = r.json()
            print("[GEETEST]", data)
            return data.get("result") == "success", data
        except Exception as e:
            return False, {"error": "geetest_error", "detail": str(e)}

    @app.get("/")
    def home():
        session.clear()
        return render_template("home.html", ms=MAX_RESPONSE_TIME_MS)

    @app.get("/step1")
    def step1():
        sid = os.urandom(16).hex()
        sessions[sid] = {
            "created": time.time(),
            "s1_captcha_done": False,
            "fx": None,
            "last_pulse_ms": 0,
            "s1_ticket": None,
        }
        session["sid"] = sid
        start_step(sessions[sid], "s1")
        return render_template(
            "step1.html",
            rc_key=RECAPTCHA_V2_SITE_KEY,
            v3_key=RECAPTCHA_V3_SITE_KEY,
            ms=MAX_RESPONSE_TIME_MS
        )

    @app.get("/step2")
    def step2():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            flash("세션 만료", "error")
            return redirect(url_for("home"))
        if not sessions[sid].get("s1_captcha_done"):
            flash("STEP1 게이트를 먼저 완료하세요", "error")
            return redirect(url_for("step1"))
        sess = sessions[sid]
        sess["s2_captcha_done"] = False
        sess["s2_ticket"] = None
        start_step(sess, "s2")
        return render_template(
            "step2.html",
            gt_id=GEETEST_CAPTCHA_ID,
            v3_key=RECAPTCHA_V3_SITE_KEY,
            ms=MAX_RESPONSE_TIME_MS
        )

    @app.get("/api/step1/status")
    def s1_status():
        ok, err = check_deadline_or_kill("s1", "s1")
        if not ok: return err
        return jsonify({"ok": True, "remaining_ms": remaining_ms("s1"),
                        "captcha_done": sessions[session["sid"]]["s1_captcha_done"]})

    @app.get("/api/step2/status")
    def s2_status():
        ok, err = check_deadline_or_kill("s2", "s2")
        if not ok: return err
        return jsonify({"ok": True, "remaining_ms": remaining_ms("s2"),
                        "captcha_done": sessions[session["sid"]].get("s2_captcha_done", False)})

    @app.post("/api/handshake/new")
    def hs_new():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        seed = secrets.token_bytes(16)
        sessions[sid]["pow"] = {"seed": seed.hex(), "ts": now_ms()}
        sessions[sid]["sig_host"] = request.host
        return jsonify(
            ok=True,
            seed=sessions[sid]["pow"]["seed"],
            bits=POW_BITS,
            bucket_ms=SIG_BUCKET_MS,
            sig_host=request.host,      
        )

    @app.post("/api/handshake/solve")
    def hs_solve():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        j = request.get_json(silent=True) or {}
        powst = sessions[sid].get("pow")
        if not powst or now_ms() - powst["ts"] > 5000:
            return jsonify({"ok": False, "reason": "pow_expired"}), 400
        nonce = str(j.get("nonce", ""))
        h = hashlib.sha256(bytes.fromhex(powst["seed"]) + nonce.encode()).digest()
        if lzbits(h) < POW_BITS:
            return jsonify({"ok": False, "reason": "pow_fail"}), 400
        key = secrets.token_hex(32)
        sessions[sid]["fx"] = {
            "key": key,
            "host": sessions[sid].get("sig_host", request.host)  
        }
        sessions[sid]["last_pulse_ms"] = 0
        return jsonify(ok=True, fx_key=key, bucket_ms=SIG_BUCKET_MS)

    @app.post("/api/pulse")
    def pulse():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sessions[sid]["last_pulse_ms"] = now_ms()
        return jsonify(ok=True)

    @app.post("/api/step1/begin")
    def s1_begin():
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s1", "s1")
        if not ok: return er
        sid = session["sid"]
        ticket = secrets.token_hex(16)
        sessions[sid]["s1_ticket"] = {"v": ticket, "ts": now_ms(), "used": False}
        return jsonify(ok=True, ticket=ticket, ttl_ms=TICKET_TTL_MS)

    @app.post("/api/step1/verify-recaptcha")
    def s1_verify_rc():
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s1", "s1")
        if not ok: return er

        sid = session["sid"]
        t = sessions[sid].get("s1_ticket")
        data = request.get_json(silent=True) or {}

        token_v2 = data.get("recaptcha_token") or request.form.get("g-recaptcha-response")
        token_v3 = data.get("v3_token")
        ticket   = data.get("ticket", "")

        if not t or t["used"] or ticket != t["v"] or now_ms() - t["ts"] > TICKET_TTL_MS:
            return jsonify({"ok": False, "reason": "ticket_invalid_or_expired"}), 400

        ok_v3, payload_v3 = verify_recaptcha_v3(token_v3, client_ip(), expected_action="s1")
        if not ok_v3:
            t["used"] = True
            return jsonify({"ok": False, "reason": payload_v3.get("error","v3_fail"),
                            "detail": payload_v3}), 400

        ok_v2, payload_v2 = verify_recaptcha_v2(token_v2, client_ip())
        if not ok_v2:
            t["used"] = True
            return jsonify({"ok": False, "reason": "recaptcha_failed", "detail": payload_v2}), 400

        t["used"] = True
        sessions[sid]["s1_captcha_done"] = True
        sessions[sid]["s1_v3_score"] = payload_v3.get("score")
        sessions[sid]["s1_v3_reasons"] = payload_v3.get("reasons")
        return jsonify({"ok": True})

    @app.post("/api/step2/begin")
    def s2_begin():
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s2", "s2")
        if not ok: return er
        sid = session["sid"]
        ticket = secrets.token_hex(16)
        sessions[sid]["s2_ticket"] = {"v": ticket, "ts": now_ms(), "used": False}
        return jsonify(ok=True, ticket=ticket, ttl_ms=TICKET_TTL_MS)

    @app.post("/api/step2/verify-slide")
    def s2_verify_slide():
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s2", "s2")
        if not ok: return er
        sid = session["sid"]
        t = sessions[sid].get("s2_ticket")
        data = request.get_json(force=True)

        if not t or t["used"] or data.get("ticket","") != t["v"] or now_ms() - t["ts"] > TICKET_TTL_MS:
            return jsonify({"ok": False, "reason": "ticket_invalid_or_expired"}), 400

        elapsed_ms = now_ms() - t["ts"]
        if elapsed_ms > GEETEST_MAX_TIME_MS:
            t["used"] = True
            return jsonify({"ok": False, "reason": "geetest_too_slow",
                           "detail": f"GeeTest must be solved within {GEETEST_MAX_TIME_MS}ms, took {elapsed_ms}ms"}), 400

        v3_token = data.get("v3_token", "")
        ok_v3, payload_v3 = verify_recaptcha_v3(v3_token, client_ip(), expected_action="s2")
        if not ok_v3:
            t["used"] = True
            return jsonify({"ok": False, "reason": payload_v3.get("error","v3_fail"), "detail": payload_v3}), 400

        ok_gt, payload_gt = verify_geetest(
            data.get("lot_number",""),
            data.get("captcha_output",""),
            data.get("pass_token",""),
            data.get("gen_time",""),
        )
        if not ok_gt:
            t["used"] = True
            return jsonify({"ok": False, "reason": "slide_failed", "detail": payload_gt}), 400

        t["used"] = True
        sessions[sid]["s2_captcha_done"] = True
        sessions[sid]["s2_v3_score"] = payload_v3.get("score")
        sessions[sid]["s2_v3_reasons"] = payload_v3.get("reasons")
        return jsonify({"ok": True})

    @app.get("/success")
    def success():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            flash("세션 만료", "error")
            return redirect(url_for("home"))
        sess = sessions[sid]
        if not (sess.get("s1_captcha_done") and sess.get("s2_captcha_done")):
            flash("모든 게이트를 완료하세요", "error")
            return redirect(url_for("step1"))
        del sessions[sid]
        session.clear()
        return render_template("success.html", flag=FLAG)

    @app.get("/diag/enterprise")
    def diag_enterprise():
        if not (RECAPTCHA_ENTERPRISE_API_KEY and RECAPTCHA_ENTERPRISE_PROJECT_ID and RECAPTCHA_V3_SITE_KEY):
            return "Missing env: RECAPTCHA_ENTERPRISE_API_KEY / RECAPTCHA_ENTERPRISE_PROJECT_ID / RECAPTCHA_V3_SITE_KEY", 500

        html = """
<!doctype html>
<meta charset="utf-8">
<title>reCAPTCHA Enterprise 진단</title>
<script src="https://www.google.com/recaptcha/enterprise.js?render={{ key }}"></script>
<style>body{font-family:sans-serif;padding:24px}pre{white-space:pre-wrap;word-break:break-all}</style>
<h1>reCAPTCHA Enterprise 진단</h1>
<p>아래 버튼을 누르면 <b>action="diag"</b>로 토큰을 발급받아 서버로 평가 호출을 보냅니다.</p>
<button id="btn">테스트 실행</button>
<pre id="out"></pre>
<script>
const out = document.getElementById('out');
function log(x){ out.textContent += (typeof x==='string'?x:JSON.stringify(x,null,2)) + "\\n"; }

async function post(url, body){
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    credentials: 'include',
    body: JSON.stringify(body)
  });
  const t = await r.json().catch(()=>({}));
  return {ok:r.ok, status:r.status, data:t};
}

document.getElementById('btn').onclick = async ()=>{
  out.textContent = "";
  log("토큰 발급 중...");
  grecaptcha.enterprise.ready(async ()=>{
    try{
      const token = await grecaptcha.enterprise.execute('{{ key }}', {action: 'diag'});
      log("token: " + token.slice(0, 20) + "…");
      const res = await post('/api/enterprise-assess', { token, action: 'diag' });
      log("status: " + res.status);
      log(res.data);
    }catch(e){
      log("토큰/호출 에러: " + e);
    }
  });
};
</script>
"""
        return render_template_string(html, key=RECAPTCHA_V3_SITE_KEY)

    @app.post("/api/enterprise-assess")
    def api_enterprise_assess():
        j = request.get_json(force=True) or {}
        token = j.get("token", "")
        action = j.get("action", "diag")

        if not token:
            return jsonify({"ok": False, "error": "missing-token"}), 400
        if not (RECAPTCHA_ENTERPRISE_API_KEY and RECAPTCHA_ENTERPRISE_PROJECT_ID and RECAPTCHA_V3_SITE_KEY):
            return jsonify({"ok": False, "error": "missing-env"}), 500

        url = (
            f"https://recaptchaenterprise.googleapis.com/v1/"
            f"projects/{RECAPTCHA_ENTERPRISE_PROJECT_ID}/assessments"
            f"?key={RECAPTCHA_ENTERPRISE_API_KEY}"
        )
        event = {
            "token": token,
            "siteKey": RECAPTCHA_V3_SITE_KEY,
            "expectedAction": action,
            "userAgent": request.headers.get("User-Agent", ""),
            "userIpAddress": (request.headers.get("X-Forwarded-For","").split(",")[0].strip()
                              or request.remote_addr or ""),
        }
        
        if request.headers.get("X-JA3"):
            event["ja3"] = request.headers.get("X-JA3")
        if request.headers.get("X-JA4"):
            event["ja4"] = request.headers.get("X-JA4")

        try:
            r = requests.post(url, json={"event": event}, timeout=8)
            data = r.json()
        except Exception as e:
            return jsonify({"ok": False, "error": "request-failed", "detail": str(e)}), 502

        tp = (data.get("tokenProperties") or {})
        ra = (data.get("riskAnalysis") or {})
        print("[diag] valid=", tp.get("valid"),
              " action=", tp.get("action"),
              " score=", ra.get("score"),
              " reasons=", ra.get("reasons"))

        return jsonify(data), r.status_code

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
