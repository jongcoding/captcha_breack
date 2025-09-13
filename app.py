import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv
load_dotenv() 
GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


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
    def verify_v3(token: str, remote_ip: str, expected_action: str):
        if not token:
            return False, {"error": "missing-token"}
        resp = requests.post(
            GOOGLE_VERIFY_URL,
            data={
                "secret": app.config["RECAPTCHA_V3_SECRET_KEY"],
                "response": token,
                "remoteip": remote_ip,
            },
            timeout=5,
        )
        data = resp.json()
        ok = bool(data.get("success"))
        # hostname/action/score 모두 확인
        host_ok = True
        expected_host = app.config.get("EXPECTED_HOSTNAME")
        if expected_host:
            host_ok = (data.get("hostname") == expected_host)
        action_ok = (data.get("action") == expected_action)
        score_ok = float(data.get("score", 0.0)) >= app.config["RECAPTCHA_V3_MIN_SCORE"]
        return (ok and host_ok and action_ok and score_ok), data

    @app.get("/v3")
    def v3_form():
        return render_template("v3.html", site_key=app.config["RECAPTCHA_V3_SITE_KEY"])

    @app.post("/v3")
    def v3_submit():
        token = request.form.get("g-recaptcha-response")
        action = request.form.get("recaptcha-action", "signup")
        ok, payload = verify_v3(token, request.remote_addr, action)
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
