#!/usr/bin/env python3
"""
Handshake 테스트 스크립트
DEV_DISABLE_SIG=0 환경에서 handshake 프로세스를 테스트합니다.
"""

import requests
import hashlib
import hmac
import time

BASE_URL = "http://localhost:80"

def solve_pow(seed_hex: str, target_bits: int) -> str:
    """PoW(Proof of Work) 풀이"""
    seed = bytes.fromhex(seed_hex)
    nonce = 0
    print(f"[*] PoW 풀이 시작 (목표: {target_bits} bits)")

    while True:
        nonce_str = str(nonce)
        h = hashlib.sha256(seed + nonce_str.encode()).digest()

        # Leading zero bits 계산
        leading_zeros = 0
        for byte in h:
            if byte == 0:
                leading_zeros += 8
                continue
            for i in range(7, -1, -1):
                if (byte >> i) & 1:
                    leading_zeros += (7 - i)
                    break
            break

        if leading_zeros >= target_bits:
            print(f"[+] PoW 해결! nonce={nonce}, leading_zeros={leading_zeros}")
            return nonce_str

        nonce += 1
        if nonce % 10000 == 0:
            print(f"    시도 중... nonce={nonce}")

def create_signature(fx_key: str, method: str, host: str, path: str, body_hash: str, bucket_ms: int) -> str:
    """요청 서명 생성"""
    timestamp_ms = int(time.time() * 1000)
    bucket = timestamp_ms // bucket_ms

    message = "\n".join([
        method.upper(),
        host,
        path,
        body_hash,
        str(bucket),
    ]).encode()

    sig = hmac.new(bytes.fromhex(fx_key), message, hashlib.sha256).hexdigest()
    return sig

def test_handshake():
    """Handshake 전체 프로세스 테스트"""
    print("=" * 60)
    print("Handshake 테스트 시작")
    print("=" * 60)

    session = requests.Session()

    # Step 1: 홈페이지 방문 (세션 초기화)
    print("\n[1] 홈페이지 방문...")
    r = session.get(f"{BASE_URL}/")
    assert r.status_code == 200, f"홈페이지 접근 실패: {r.status_code}"
    print("[+] 세션 초기화 완료")

    # Step 2: /step1 방문 (세션 생성)
    print("\n[2] Step1 페이지 방문...")
    r = session.get(f"{BASE_URL}/step1")
    assert r.status_code == 200, f"Step1 접근 실패: {r.status_code}"
    print(f"[+] 세션 생성 완료 (쿠키: {session.cookies.get_dict()})")

    # Step 3: Handshake 시작 - PoW 챌린지 요청
    print("\n[3] Handshake 챌린지 요청...")
    r = session.post(f"{BASE_URL}/api/handshake/new")
    assert r.status_code == 200, f"Handshake new 실패: {r.status_code} {r.text}"

    data = r.json()
    assert data["ok"], f"Handshake new 실패: {data}"

    seed = data["seed"]
    bits = data["bits"]
    bucket_ms = data["bucket_ms"]
    sig_host = data["sig_host"]

    print(f"[+] PoW 챌린지 수신:")
    print(f"    - seed: {seed}")
    print(f"    - bits: {bits}")
    print(f"    - bucket_ms: {bucket_ms}")
    print(f"    - sig_host: {sig_host}")

    # Step 4: PoW 풀이
    print("\n[4] PoW 풀이 중...")
    nonce = solve_pow(seed, bits)

    # Step 5: PoW 제출 및 fx_key 획득
    print("\n[5] PoW 솔루션 제출...")
    r = session.post(
        f"{BASE_URL}/api/handshake/solve",
        json={"nonce": nonce}
    )
    assert r.status_code == 200, f"Handshake solve 실패: {r.status_code} {r.text}"

    data = r.json()
    assert data["ok"], f"Handshake solve 실패: {data}"

    fx_key = data["fx_key"]
    print(f"[+] Handshake 성공!")
    print(f"    - fx_key: {fx_key}")

    # Step 6: Pulse 전송
    print("\n[6] Pulse 전송...")
    r = session.post(f"{BASE_URL}/api/pulse")
    assert r.status_code == 200, f"Pulse 실패: {r.status_code} {r.text}"
    print("[+] Pulse 전송 완료")

    # Step 7: 서명된 요청 테스트 (/api/step1/begin)
    print("\n[7] 서명된 요청 테스트...")
    method = "POST"
    path = "/api/step1/begin"
    body = b""
    body_hash = hashlib.sha256(body).hexdigest()

    sig = create_signature(fx_key, method, sig_host, path, body_hash, bucket_ms)
    print(f"[+] 서명 생성 완료: {sig[:32]}...")

    headers = {"X-Fx-Stealth": sig}  # .env의 FX_HDR_NAME과 일치
    r = session.post(f"{BASE_URL}{path}", headers=headers)

    print(f"    - 응답 코드: {r.status_code}")
    print(f"    - 응답 본문: {r.text}")

    if r.status_code == 200:
        data = r.json()
        if data.get("ok"):
            print("\n" + "=" * 60)
            print("SUCCESS! Handshake 완전히 성공!")
            print(f"Step1 티켓: {data.get('ticket')}")
            print("=" * 60)
            return True
        else:
            print(f"\n[!] 요청은 성공했지만 응답이 ok=False: {data}")
            return False
    else:
        print(f"\n[!] 서명된 요청 실패: {r.status_code}")
        print(f"    응답: {r.text}")
        return False

if __name__ == "__main__":
    try:
        success = test_handshake()
        exit(0 if success else 1)
    except AssertionError as e:
        print(f"\n[ERROR] {e}")
        exit(1)
    except Exception as e:
        print(f"\n[ERROR] 예상치 못한 오류: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
