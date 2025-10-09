import os
import hmac
import hashlib
import time
import secrets
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from dotenv import load_dotenv

load_dotenv()

GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
GEETEST_VALIDATE_URL = "https://gcaptcha4.geetest.com/validate"

RECAPTCHA_ENTERPRISE_API_KEY    = os.getenv("RECAPTCHA_ENTERPRISE_API_KEY", "")
RECAPTCHA_ENTERPRISE_PROJECT_ID = os.getenv("RECAPTCHA_ENTERPRISE_PROJECT_ID", "")

FLAG = os.getenv("FLAG", "MSG{FAKE_FLAG}")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

MAX_RESPONSE_TIME_MS = int(os.getenv("MAX_RESPONSE_TIME_MS", "60000"))

SIG_BUCKET_MS    = int(os.getenv("SIG_BUCKET_MS", "120"))
PULSE_MAX_AGE_MS = int(os.getenv("PULSE_MAX_AGE_MS", "320"))
POW_BITS         = int(os.getenv("POW_BITS", "18"))
TICKET_TTL_MS    = int(os.getenv("TICKET_TTL_MS", "3000"))
GEETEST_MAX_TIME_MS = int(os.getenv("GEETEST_MAX_TIME_MS", "60000"))
FX_HDR_NAME      = os.getenv("FX_HDR_NAME", "X-Fx-Sig")
BLOCK_BROWSER    = os.getenv("BLOCK_BROWSER", "1") == "1"

DEV_DISABLE_SIG = os.getenv("DEV_DISABLE_SIG", "0") == "1"

RECAPTCHA_V2_SITE_KEY   = os.getenv("RECAPTCHA_V2_SITE_KEY", "")
RECAPTCHA_V2_SECRET_KEY = os.getenv("RECAPTCHA_V2_SECRET_KEY", "")
RECAPTCHA_V3_SITE_KEY   = os.getenv("RECAPTCHA_V3_SITE_KEY", "")
RECAPTCHA_V3_SECRET_KEY = os.getenv("RECAPTCHA_V3_SECRET_KEY", "")

V3_HUMAN_MIN    = float(os.getenv("V3_HUMAN_MIN", "0.95"))
V3_ACCEPT_MAX   = float(os.getenv("V3_ACCEPT_MAX","0.90"))
V3_MID_TREAT_AS = os.getenv("V3_MID_TREAT_AS", "reject")

EXPECTED_HOSTNAME   = os.getenv("EXPECTED_HOSTNAME")
GEETEST_CAPTCHA_ID  = os.getenv("GEETEST_CAPTCHA_ID", "")
GEETEST_CAPTCHA_KEY = os.getenv("GEETEST_CAPTCHA_KEY", "")

JA3_BADLIST = set(x.strip() for x in os.getenv("JA3_BADLIST", "").split(",") if x.strip())
JA4_BADLIST = set(x.strip() for x in os.getenv("JA4_BADLIST", "").split(",") if x.strip())

API_BROWSER_ALLOWLIST = {
    "/api/step2/begin",
    "/api/step2/verify-slide",
    "/api/step2/status",
}

S1_TO_S2_MAX_MS = int(os.getenv("S1_TO_S2_MAX_MS", "60000"))

def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    sessions = {}

    def now_ms() -> int:
        return int(time.time() * 1000)

    def sha256_body() -> str:
        body = request.get_data(cache=True) or b""
        return hashlib.sha256(body).hexdigest()

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

    def require_sig_and_pulse():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        st = sessions[sid].get("fx")
        if not st:
            return jsonify({"ok": False, "reason": "no_handshake"}), 403

        if not DEV_DISABLE_SIG:
            sig_hdr = request.headers.get(FX_HDR_NAME, "")
            sig_ck1 = request.cookies.get("fxsig", "")
            sig_ck2 = request.cookies.get("fx_sig", "")
            sig_q1  = request.args.get("_fx", "")
            sig_q2  = request.args.get("fx", "")
            sig = sig_hdr or sig_ck1 or sig_ck2 or sig_q1 or sig_q2
            if not sig:
                return jsonify({"ok": False, "reason": "bad_signature"}), 403

            bkt_now = now_ms() // SIG_BUCKET_MS
            buckets = (bkt_now - 1, bkt_now, bkt_now + 1)
            host_base = (st.get("host") or request.host or request.headers.get("Host", ""))
            candidates = set()
            for h in (host_base, request.host, request.headers.get("Host", ""), request.headers.get("X-Forwarded-Host", "")):
                candidates.update(_host_variants(h or ""))
            ok = False
            for h in candidates or [request.host]:
                for b in buckets:
                    msg = "\n".join([
                        request.method.upper(),
                        h,
                        request.path,
                        sha256_body(),
                        str(b),
                    ]).encode()
                    expect = hmac.new(bytes.fromhex(st["key"]), msg, hashlib.sha256).hexdigest()
                    if hmac.compare_digest(sig, expect):
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                return jsonify({"ok": False, "reason": "bad_signature"}), 403

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
            if sid in sessions:
                del sessions[sid]
            session.clear()
            return False, (jsonify({"ok": False, "reason": "timeout", "killed": True}), 400)
        return True, None

    def remaining_ms(step_key: str) -> int:
        sid = session.get("sid")
        sess = sessions[sid]
        return max(0, int((sess[f"{step_key}_expire"] - time.monotonic()) * 1000))

    def kill_session():
        sid = session.get("sid")
        if sid and sid in sessions:
            del sessions[sid]
        session.clear()

    def _hostname_ok(payload: dict) -> bool:
        if not EXPECTED_HOSTNAME:
            return True
        allowed = [h.strip() for h in str(EXPECTED_HOSTNAME).split(",") if h.strip()]
        return (payload.get("hostname") in allowed)

    def verify_recaptcha_v2(token: str, remote_ip: str):
        if not token:
            return False, {"error": "missing-token"}
        data = {"secret": RECAPTCHA_V2_SECRET_KEY, "response": token, "remoteip": remote_ip}
        try:
            resp = requests.post(GOOGLE_VERIFY_URL, data=data, timeout=5)
            payload = resp.json()
        except Exception as e:
            return False, {"error": "recaptcha_request_error", "detail": str(e)}
        ok = bool(payload.get("success")) and _hostname_ok(payload)
        return ok, payload

    def verify_recaptcha_v3(token: str, remote_ip: str, expected_action: str = None):
        if not token:
            return False, {"error": "v3_token_required"}
        if RECAPTCHA_ENTERPRISE_API_KEY and RECAPTCHA_ENTERPRISE_PROJECT_ID and RECAPTCHA_V3_SITE_KEY:
            url = (
                f"https://recaptchaenterprise.googleapis.com/v1/projects/"
                f"{RECAPTCHA_ENTERPRISE_PROJECT_ID}/assessments?key={RECAPTCHA_ENTERPRISE_API_KEY}"
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
            return False, {"error": "score_mid_zone", "score": score, "reasons": reasons}
        data = {"secret": RECAPTCHA_V3_SECRET_KEY, "response": token, "remoteip": remote_ip}
        try:
            resp = requests.post(GOOGLE_VERIFY_URL, data=data, timeout=5)
            payload = resp.json()
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
        sign_token = hmac.new(GEETEST_CAPTCHA_KEY.encode("utf-8"), lot_number.encode("utf-8"), hashlib.sha256).hexdigest()
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
        return render_template("step1.html", rc_key=RECAPTCHA_V2_SITE_KEY, v3_key=RECAPTCHA_V3_SITE_KEY, ms=MAX_RESPONSE_TIME_MS)

    @app.get("/step2")
    def step2():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            flash("Session expired", "error")
            return redirect(url_for("home"))
        if not sessions[sid].get("s1_captcha_done"):
            flash("Complete Step 1 first", "error")
            return redirect(url_for("step1"))
        exp = sessions[sid].get("s1_to_s2_expire")
        if exp and now_ms() > exp:
            kill_session()
            flash("Too late for Step 2", "error")
            return redirect(url_for("home"))
        sess = sessions[sid]
        sess["s2_captcha_done"] = False
        sess["s2_ticket"] = None
        start_step(sess, "s2")
        return render_template("step2.html", gt_id=GEETEST_CAPTCHA_ID, v3_key=RECAPTCHA_V3_SITE_KEY, ms=MAX_RESPONSE_TIME_MS)

    @app.get("/api/step1/status")
    def s1_status():
        ok, err = check_deadline_or_kill("s1", "s1")
        if not ok: return err
        return jsonify({"ok": True, "remaining_ms": remaining_ms("s1"), "captcha_done": sessions[session["sid"]]["s1_captcha_done"]})

    @app.get("/api/step2/status")
    def s2_status():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        exp = sessions[sid].get("s1_to_s2_expire")
        if exp and now_ms() > exp:
            kill_session()
            return jsonify({"ok": False, "reason": "s1_to_s2_timeout", "killed": True}), 400
        ok, err = check_deadline_or_kill("s2", "s2")
        if not ok: return err
        return jsonify({"ok": True, "remaining_ms": remaining_ms("s2"), "captcha_done": sessions[sid].get("s2_captcha_done", False)})

    @app.post("/api/handshake/new")
    def hs_new():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        seed = secrets.token_bytes(16)
        sessions[sid]["pow"] = {"seed": seed.hex(), "ts": now_ms()}
        sessions[sid]["sig_host"] = request.host
        return jsonify(ok=True, seed=sessions[sid]["pow"]["seed"], bits=POW_BITS, bucket_ms=SIG_BUCKET_MS, sig_host=request.host)

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
        sessions[sid]["fx"] = {"key": key, "host": sessions[sid].get("sig_host", request.host)}
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
            return jsonify({"ok": False, "reason": payload_v3.get("error","v3_fail"), "detail": payload_v3}), 400
        ok_v2, payload_v2 = verify_recaptcha_v2(token_v2, client_ip())
        if not ok_v2:
            t["used"] = True
            return jsonify({"ok": False, "reason": "recaptcha_failed", "detail": payload_v2}), 400
        t["used"] = True
        sessions[sid]["s1_captcha_done"] = True
        sessions[sid]["s1_v3_score"] = payload_v3.get("score")
        sessions[sid]["s1_v3_reasons"] = payload_v3.get("reasons")
        sessions[sid]["s1_to_s2_expire"] = now_ms() + S1_TO_S2_MAX_MS
        return jsonify({"ok": True})

    @app.post("/api/step2/begin")
    def s2_begin():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        exp = sessions[sid].get("s1_to_s2_expire")
        if exp and now_ms() > exp:
            kill_session()
            return jsonify({"ok": False, "reason": "s1_to_s2_timeout", "killed": True}), 400
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s2", "s2")
        if not ok: return er
        ticket = secrets.token_hex(16)
        sessions[sid]["s2_ticket"] = {"v": ticket, "ts": now_ms(), "used": False}
        return jsonify(ok=True, ticket=ticket, ttl_ms=TICKET_TTL_MS)

    @app.post("/api/step2/verify-slide")
    def s2_verify_slide():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        exp = sessions[sid].get("s1_to_s2_expire")
        if exp and now_ms() > exp:
            kill_session()
            return jsonify({"ok": False, "reason": "s1_to_s2_timeout", "killed": True}), 400
        err = require_sig_and_pulse()
        if err: return err
        ok, er = check_deadline_or_kill("s2", "s2")
        if not ok: return er
        t = sessions[sid].get("s2_ticket")
        data = request.get_json(force=True)
        if not t or t["used"] or data.get("ticket","") != t["v"] or now_ms() - t["ts"] > TICKET_TTL_MS:
            return jsonify({"ok": False, "reason": "ticket_invalid_or_expired"}), 400
        elapsed_ms = now_ms() - t["ts"]
        if elapsed_ms > GEETEST_MAX_TIME_MS:
            t["used"] = True
            return jsonify({"ok": False, "reason": "geetest_too_slow", "detail": f"GeeTest must be solved within {GEETEST_MAX_TIME_MS}ms, took {elapsed_ms}ms"}), 400
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
            flash("Session expired", "error")
            return redirect(url_for("home"))
        sess = sessions[sid]
        if not (sess.get("s1_captcha_done") and sess.get("s2_captcha_done")):
            flash("Complete all gates", "error")
            return redirect(url_for("step1"))
        del sessions[sid]
        session.clear()
        return render_template("success.html", flag=FLAG)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(port=5000, debug=False)
