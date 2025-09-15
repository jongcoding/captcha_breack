import os, hmac, hashlib, json
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from dotenv import load_dotenv
load_dotenv() 

GEETEST_CAPTCHA_ID = os.getenv("GEETEST_CAPTCHA_ID", "")
GEETEST_CAPTCHA_KEY = os.getenv("GEETEST_CAPTCHA_KEY", "")
GEETEST_VALIDATE_URL = "https://gcaptcha4.geetest.com/validate"  # v4 2차검증 엔드포인트

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

    # 환경설정
    app.config.update(
        RECAPTCHA_V2_SITE_KEY=os.getenv("RECAPTCHA_V2_SITE_KEY", ""),
        RECAPTCHA_V2_SECRET_KEY=os.getenv("RECAPTCHA_V2_SECRET_KEY", ""),
        RECAPTCHA_V3_SITE_KEY=os.getenv("RECAPTCHA_V3_SITE_KEY", ""),
        RECAPTCHA_V3_SECRET_KEY=os.getenv("RECAPTCHA_V3_SECRET_KEY", ""),
        EXPECTED_HOSTNAME=os.getenv("EXPECTED_HOSTNAME"),          # e.g., "localhost" or "your.domain"
        RECAPTCHA_V3_MIN_SCORE=float(os.getenv("RECAPTCHA_V3_MIN_SCORE", 0.5)),
    )

    @app.get("/")
    def home():
        return render_template("base.html")

    # ---------------------
    # v1 
    # ---------------------
    @app.get("/v1")
    def v1_form():
        return render_template("v1.html")

    @app.post("/v1")
    def v1_submit():
        # ⚠️ 클라이언트(JS)에서만 2+3=5 확인, 서버는 검증 없음 → 우회 가능 (학습용)
        username = request.form.get("username")
        flash(f"[v1] 캡차 미검증 상태로 통과: {username}", "ok")
        return redirect(url_for("v1_form"))

    # ---------------------
    # reCAPTCHA v2
    # ---------------------
    def verify_v2(token: str, remote_ip: str):
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
        # hostname 일치 체크
        host_ok = True
        expected = app.config.get("EXPECTED_HOSTNAME")
        if expected:
            host_ok = (data.get("hostname") == expected)
        return (ok and host_ok), data

    @app.get("/v2")
    def v2_form():
        return render_template("v2.html", site_key=app.config["RECAPTCHA_V2_SITE_KEY"])

    @app.post("/v2")
    def v2_submit():
        token = request.form.get("g-recaptcha-response")
        ok, payload = verify_v2(token, request.remote_addr)
        if not ok:
            flash(f"[v2] reCAPTCHA 실패: {payload}", "err")
            return redirect(url_for("v2_form"))
        flash("[v2] reCAPTCHA 통과", "ok")
        return redirect(url_for("v2_form"))

    # ---------------------
    # reCAPTCHA v3
    # ---------------------

    @app.get("/v3")
    def v3_form():
        return render_template("v3.html", captcha_id=GEETEST_CAPTCHA_ID)

    @app.post("/v3")
    def v3_verify():
        """
        클라이언트로부터 lot_number, captcha_output, pass_token, gen_time 수신
        → 서버에서 sign_token(HMAC-SHA256(lot_number, key)) 생성
        → Geetest /validate 로 전송하여 결과 확인
        """
        data = request.get_json(force=True)
        lot_number = data.get("lot_number", "")
        captcha_output = data.get("captcha_output", "")
        pass_token = data.get("pass_token", "")
        gen_time = data.get("gen_time", "")

        if not (GEETEST_CAPTCHA_ID and GEETEST_CAPTCHA_KEY):
            return jsonify({"ok": False, "reason": "server_not_configured"}), 500

        if not (lot_number and captcha_output and pass_token and gen_time):
            return jsonify({"ok": False, "reason": "missing_params"}), 400

        # v4 사양: sign_token = HMAC_SHA256(key, lot_number)
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

        # 권장: captcha_id를 쿼리스트링으로 붙여 로그 트레이싱 용이
        url = f"{GEETEST_VALIDATE_URL}?captcha_id={GEETEST_CAPTCHA_ID}"

        try:
            res = requests.post(url, data=payload, timeout=5)
            res.raise_for_status()
            result = res.json()
        except Exception as e:
            # 장애/타임아웃 시, 비즈니스 로직 차단 방지를 위해 실패로 회신
            return jsonify({"ok": False, "reason": "geetest_unreachable", "detail": str(e)}), 502

        # v4 응답: result == "success" 면 통과
        ok = (result.get("result") == "success")
        
        if not ok:
            # 안전한 폴백: 점수/action/hostname 불일치 시 v2로 유도
            flash(f"[v3] score/action/host 조건 미충족 → v2로 이동: {payload}", "warn")
            return redirect(url_for("v2_form"))
        flash("[v3] reCAPTCHA(v3) 통과", "ok")
        return redirect(url_for("v3_form"))

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
