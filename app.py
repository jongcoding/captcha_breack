import os
import hmac
import hashlib
import time
import random
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from dotenv import load_dotenv

load_dotenv()

GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
GEETEST_VALIDATE_URL = "https://gcaptcha4.geetest.com/validate"

# 각 문제의 제한시간(ms). 운영에서는 2500~4000 권장.
MAX_RESPONSE_TIME_MS = int(os.getenv("MAX_RESPONSE_TIME_MS", "10000"))
FLAG = os.getenv("FLAG", "FLAG{d0ubl3_c4ptch4_m4th_m4st3r}")

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
    app.config.update(
        RECAPTCHA_V2_SITE_KEY=os.getenv("RECAPTCHA_V2_SITE_KEY", ""),
        RECAPTCHA_V2_SECRET_KEY=os.getenv("RECAPTCHA_V2_SECRET_KEY", ""),
        # 개발 중이면 비우거나 'localhost,127.0.0.1' 로 설정
        EXPECTED_HOSTNAME=os.getenv("EXPECTED_HOSTNAME"),
        GEETEST_CAPTCHA_ID=os.getenv("GEETEST_CAPTCHA_ID", ""),
        GEETEST_CAPTCHA_KEY=os.getenv("GEETEST_CAPTCHA_KEY", "")
    )

    sessions = {}

    # ------------- helpers -------------
    def generate_math_problem():
        ops = [
            lambda: (random.randint(10, 99), random.randint(10, 99), '+', lambda a, b: a + b),
            lambda: (random.randint(10, 99), random.randint(10, 99), '*', lambda a, b: a * b),
            lambda: (random.randint(100, 999), random.randint(10, 99), '-', lambda a, b: a - b),
        ]
        a, b, op, fn = random.choice(ops)()
        return f"{a} {op} {b}", fn(a, b)

    def start_new_problem(sess, step_key):
        prob, ans = generate_math_problem()
        now = time.monotonic()
        sess[f"{step_key}_problem"] = prob
        sess[f"{step_key}_answer"] = ans
        sess[f"{step_key}_started"] = now
        sess[f"{step_key}_expire"] = now + MAX_RESPONSE_TIME_MS / 1000.0
        sess[f"{step_key}_count"] = sess.get(f"{step_key}_count", 0) + 1

    def check_deadline_or_kill(sess, step_key, reason_prefix):
        # 캡챠가 끝났다면 더 이상 시간제한에 걸리지 않게 (완료 상태)
        if sess.get(f"{step_key}_captcha_done"):
            return True, None
        now = time.monotonic()
        if now > sess.get(f"{step_key}_expire", 0):
            kill_session(f"{reason_prefix}_timeout")
            return False, {"ok": False, "reason": "timeout", "killed": True}
        return True, None

    def verify_recaptcha_v2(token: str, remote_ip: str):
        if not token:
            return False, {"error": "missing-token"}
        resp = requests.post(
            GOOGLE_VERIFY_URL,
            data={
                "secret": app.config["RECAPTCHA_V2_SECRET_KEY"],
                "response": token,
                "remoteip": remote_ip,
            },
            timeout=5,
        )
        data = resp.json()
        ok = bool(data.get("success"))
        host_ok = True
        expected = app.config.get("EXPECTED_HOSTNAME")
        if expected:
            allowed = [h.strip() for h in str(expected).split(",") if h.strip()]
            host_ok = (data.get("hostname") in allowed)
        print("[RECAPTCHA]", data)
        return (ok and host_ok), data

    def verify_geetest(lot_number, captcha_output, pass_token, gen_time):
        if not all([lot_number, captcha_output, pass_token, gen_time]):
            return False, {"error": "missing_params"}
        sign_token = hmac.new(
            app.config["GEETEST_CAPTCHA_KEY"].encode("utf-8"),
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
        url = f"{GEETEST_VALIDATE_URL}?captcha_id={app.config['GEETEST_CAPTCHA_ID']}"
        try:
            r = requests.post(url, data=payload, timeout=5)
            r.raise_for_status()
            data = r.json()
            print("[GEETEST]", data)
            return data.get("result") == "success", data
        except Exception as e:
            return False, {"error": "geetest_error", "detail": str(e)}

    def kill_session(reason="unknown"):
        sid = session.get("sid")
        if sid and sid in sessions:
            print(f"[KILL] {sid} : {reason}")
            del sessions[sid]
        session.clear()
        return reason

    # ------------- routes -------------
    @app.get("/")
    def home():
        session.clear()
        return render_template("home.html", ms=MAX_RESPONSE_TIME_MS)

    # STEP1 초기화
    @app.get("/step1")
    def step1():
        sid = os.urandom(16).hex()
        sessions[sid] = {
            "created": time.time(),
            # step1 상태
            "s1_captcha_done": False,
            "s1_count": 0
        }
        session["sid"] = sid
        start_new_problem(sessions[sid], "s1")
        return render_template(
            "step1.html",
            problem=sessions[sid]["s1_problem"],
            rc_key=app.config["RECAPTCHA_V2_SITE_KEY"],
            ms=MAX_RESPONSE_TIME_MS
        )

    # STEP1 상태 폴링
    @app.get("/api/step1/status")
    def s1_status():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]
        ok, err = check_deadline_or_kill(sess, "s1", "s1")
        if not ok:
            return jsonify(err), 400
        remain = max(0, int((sess["s1_expire"] - time.monotonic()) * 1000))
        return jsonify({"ok": True, "remaining_ms": remain, "captcha_done": sess["s1_captcha_done"]})

    # STEP1 수학 제출 (정답이면 즉시 다음 문제 생성, 늦거나 오답이면 kill)
    @app.post("/api/step1/answer")
    def s1_answer():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]
        if sess.get("s1_captcha_done"):
            return jsonify({"ok": False, "reason": "already_completed"}), 400

        ok, err = check_deadline_or_kill(sess, "s1", "s1")
        if not ok:
            return jsonify(err), 400

        data = request.get_json(force=True)
        try:
            user_ans = int(data.get("answer"))
        except:
            kill_session("s1_invalid_answer")
            return jsonify({"ok": False, "reason": "invalid_answer", "killed": True}), 400

        if user_ans != sess["s1_answer"]:
            kill_session("s1_wrong")
            return jsonify({"ok": False, "reason": "wrong_answer", "killed": True}), 400

        # 정답 → 다음 문제
        start_new_problem(sess, "s1")
        remain = max(0, int((sess["s1_expire"] - time.monotonic()) * 1000))
        return jsonify({"ok": True, "problem": sess["s1_problem"], "remaining_ms": remain})

    # STEP1 reCAPTCHA (언제든 1회). 현재 문제가 이미 만료면 그 즉시 kill.
    @app.post("/api/step1/verify-recaptcha")
    def s1_verify_rc():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]

        ok, err = check_deadline_or_kill(sess, "s1", "s1")
        if not ok:
            return jsonify(err), 400

        data = request.get_json(silent=True) or {}
        token = data.get("recaptcha_token") or request.form.get("g-recaptcha-response")
        ok, payload = verify_recaptcha_v2(token, request.remote_addr)
        if not ok:
            return jsonify({"ok": False, "reason": "recaptcha_failed", "detail": payload}), 400

        sess["s1_captcha_done"] = True
        return jsonify({"ok": True})

    # STEP2 초기화 (STEP1 reCAPTCHA 완료 필수)
    @app.get("/step2")
    def step2():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            flash("세션 만료", "error")
            return redirect(url_for("home"))
        sess = sessions[sid]
        if not sess.get("s1_captcha_done"):
            flash("STEP1 reCAPTCHA를 먼저 완료하세요", "error")
            return redirect(url_for("step1"))

        # STEP2 준비
        sess["s2_captcha_done"] = False
        sess["s2_count"] = 0
        start_new_problem(sess, "s2")

        return render_template(
            "step2.html",
            problem=sess["s2_problem"],
            gt_id=app.config["GEETEST_CAPTCHA_ID"],
            ms=MAX_RESPONSE_TIME_MS
        )

    # STEP2 상태 폴링
    @app.get("/api/step2/status")
    def s2_status():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]
        ok, err = check_deadline_or_kill(sess, "s2", "s2")
        if not ok:
            return jsonify(err), 400
        remain = max(0, int((sess["s2_expire"] - time.monotonic()) * 1000))
        return jsonify({"ok": True, "remaining_ms": remain, "captcha_done": sess["s2_captcha_done"]})

    # STEP2 수학 제출
    @app.post("/api/step2/answer")
    def s2_answer():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]
        if sess.get("s2_captcha_done"):
            return jsonify({"ok": False, "reason": "already_completed"}), 400

        ok, err = check_deadline_or_kill(sess, "s2", "s2")
        if not ok:
            return jsonify(err), 400

        data = request.get_json(force=True)
        try:
            user_ans = int(data.get("answer"))
        except:
            kill_session("s2_invalid_answer")
            return jsonify({"ok": False, "reason": "invalid_answer", "killed": True}), 400

        if user_ans != sess["s2_answer"]:
            kill_session("s2_wrong")
            return jsonify({"ok": False, "reason": "wrong_answer", "killed": True}), 400

        start_new_problem(sess, "s2")
        remain = max(0, int((sess["s2_expire"] - time.monotonic()) * 1000))
        return jsonify({"ok": True, "problem": sess["s2_problem"], "remaining_ms": remain})

    # STEP2 GeeTest (언제든 1회). 현재 문제 시간 초과면 kill.
    @app.post("/api/step2/verify-slide")
    def s2_verify_slide():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            return jsonify({"ok": False, "reason": "session_expired"}), 401
        sess = sessions[sid]

        ok, err = check_deadline_or_kill(sess, "s2", "s2")
        if not ok:
            return jsonify(err), 400

        data = request.get_json(force=True)
        ok, payload = verify_geetest(
            data.get("lot_number",""),
            data.get("captcha_output",""),
            data.get("pass_token",""),
            data.get("gen_time",""),
        )
        if not ok:
            return jsonify({"ok": False, "reason": "slide_failed", "detail": payload}), 400

        sess["s2_captcha_done"] = True
        return jsonify({"ok": True})

    @app.get("/success")
    def success():
        sid = session.get("sid")
        if not sid or sid not in sessions:
            flash("세션 만료", "error")
            return redirect(url_for("home"))
        sess = sessions[sid]
        if not (sess.get("s1_captcha_done") and sess.get("s2_captcha_done")):
            flash("모든 캡챠를 완료하세요", "error")
            return redirect(url_for("step1"))

        # 여기까지 왔다는 건 하나도 시간초과/오답이 없었다는 의미
        del sessions[sid]
        session.clear()
        return render_template("success.html", flag=FLAG)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
