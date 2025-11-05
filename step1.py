

import os
import time
import hashlib
import hmac
import re
import json
import pickle
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

try:
    from solver.behavior import human_like_move_and_click
    from solver.image import ImageSolver
    SOLVER_AVAILABLE = True
except ImportError:
    SOLVER_AVAILABLE = False

# ============== 설정 ==============
TARGET_URL = "http://captcha2.mjsec.kr"
#TARGET_URL="http://localhost"
PROXY_PORT = 8888
PROXY_HOST = "127.0.0.1"

YOLO_CLS_WEIGHTS = "weights/final.pt"
YOLO_SEG_WEIGHTS = "weights/yolo_seg.pt"
YOLO_SECOND_WEIGHTS = "weights/yolo_cls.pt"

USE_SECONDARY = {"오토바이", "자전거", "motorcycle", "bicycle", "motorcycles", "bicycles"}

SESSION_FILE = "session_data.pkl"

# ============== Firefox with Proxy ==============
def create_firefox_with_proxy():
    """Firefox with proxy"""
    options = FirefoxOptions()
    options.set_preference("dom.webdriver.enabled", False)
    options.set_preference("useAutomationExtension", False)
    options.set_preference("general.useragent.override",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")
    options.set_preference("network.proxy.type", 1)
    options.set_preference("network.proxy.http", PROXY_HOST)
    options.set_preference("network.proxy.http_port", PROXY_PORT)
    options.set_preference("network.proxy.ssl", PROXY_HOST)
    options.set_preference("network.proxy.ssl_port", PROXY_PORT)
    options.set_preference("network.proxy.no_proxies_on", "")
    options.set_preference("network.proxy.allow_hijacking_localhost", True)
    options.accept_insecure_certs = True
    return webdriver.Firefox(options=options)

# ============== reCAPTCHA 헬퍼 ==============
def scroll_into_view(driver, element):
    try:
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
        time.sleep(0.3)
    except:
        pass

def safe_click(driver, element):
    try:
        scroll_into_view(driver, element)
        if SOLVER_AVAILABLE:
            human_like_move_and_click(driver, element, duration=0.4)
        else:
            element.click()
    except:
        element.click()

def click_recaptcha_checkbox(driver, wait):
    try:
        iframe = wait.until(EC.presence_of_element_located(
            (By.CSS_SELECTOR, "iframe[title='reCAPTCHA']")))
        driver.switch_to.frame(iframe)
        checkbox = wait.until(EC.element_to_be_clickable(
            (By.CLASS_NAME, "recaptcha-checkbox-border")))
        safe_click(driver, checkbox)
    finally:
        driver.switch_to.default_content()
        time.sleep(0.5)

def check_recaptcha_solved(driver):
    try:
        driver.switch_to.default_content()
        wait = WebDriverWait(driver, 2)
        wait.until(EC.frame_to_be_available_and_switch_to_it(
            (By.CSS_SELECTOR, "iframe[title='reCAPTCHA']")))
        wait.until(EC.presence_of_element_located(
            (By.CSS_SELECTOR, ".recaptcha-checkbox-checked")))
        driver.switch_to.default_content()
        return True
    except TimeoutException:
        driver.switch_to.default_content()
        try:
            resp = driver.find_element(By.CSS_SELECTOR, "textarea[name='g-recaptcha-response']")
            return bool(resp.get_attribute("value").strip())
        except:
            return False

def solve_image_challenge(driver, wait, solver, solver_seg, max_image_attempts=3):
    """이미지 챌린지 풀이"""
    def enter_challenge_iframe():
        try:
            img_iframe = wait.until(EC.presence_of_element_located(
                (By.XPATH, "//iframe[contains(@title,'보안문자') or contains(@title,'challenge')]")))
            driver.switch_to.frame(img_iframe)
            return True
        except TimeoutException:
            return False

    if not enter_challenge_iframe():
        return False

    attempt = 0
    while attempt < max_image_attempts:
        attempt += 1
        print(f"    [Image Attempt {attempt}/{max_image_attempts}]")
        
        try:
            payload = wait.until(EC.presence_of_element_located(
                (By.CSS_SELECTOR, "div.rc-imageselect-payload")))
            target_text = payload.find_element(By.TAG_NAME, "strong").text.strip()
            print(f"    [Challenge] Target: {target_text}")
            
            solver_to_use = solver_seg if target_text in USE_SECONDARY else solver
            
            tile_elements = driver.find_elements(By.CSS_SELECTOR, "td.rc-imageselect-tile")
            num_tiles = len(tile_elements)
            grid_size = '3x3' if num_tiles == 9 else '4x4'
            
            if num_tiles not in (9, 16):
                driver.switch_to.default_content()
                return False
            
            puzzle_root = driver.find_element(
                By.XPATH, "//table[contains(@class,'rc-imageselect-table-')]")
            
            clicked_indices = []
            
            if grid_size == '3x3':
                clicked_indices = solver_to_use.solve_3x3(driver, puzzle_root)
                if clicked_indices:
                    solver_to_use.solve_until_done(driver, puzzle_root, grid_size='3x3', max_attempts=5)
            else:
                clicked_indices = solver_to_use.solve_4x4(driver, puzzle_root)
            
            if clicked_indices:
                verify_btn = wait.until(EC.element_to_be_clickable(
                    (By.ID, "recaptcha-verify-button")))
                safe_click(driver, verify_btn)
                time.sleep(2)
                
                if check_recaptcha_solved(driver):
                    return True
                
                driver.switch_to.default_content()
                if not enter_challenge_iframe():
                    continue
            else:
                reload_btn = wait.until(EC.element_to_be_clickable(
                    (By.ID, "recaptcha-reload-button")))
                safe_click(driver, reload_btn)
                time.sleep(1)
                driver.switch_to.default_content()
                if not enter_challenge_iframe():
                    continue
                    
        except Exception as e:
            print(f"    [Error] {e}")
            driver.switch_to.default_content()
            if not enter_challenge_iframe():
                return False
    
    driver.switch_to.default_content()
    return False

def extract_token(driver):
    try:
        driver.switch_to.default_content()
        token_element = driver.find_element(By.NAME, "g-recaptcha-response")
        token = token_element.get_attribute("value")
        if token:
            return token
    except:
        pass
    return None

# ============== Step1 Solver ==============
class Step1Solver:
    def __init__(self, target_url):
        self.target_url = target_url
        self.driver = None
        self.wait = None
        self.fx_key = None
        self.bucket_ms = 120
        self.sig_host = None
        
        if SOLVER_AVAILABLE:
            self.solver = ImageSolver(YOLO_CLS_WEIGHTS, YOLO_SEG_WEIGHTS)
            self.solver_seg = ImageSolver(YOLO_SECOND_WEIGHTS, YOLO_SEG_WEIGHTS)
        else:
            self.solver = None
            self.solver_seg = None
    
    def setup(self):
        print("\n" + "="*60)
        print("STEP1 SOLVER SETUP")
        print("="*60 + "\n")
        
        print(f"[*] Starting Firefox with proxy...")
        self.driver = create_firefox_with_proxy()
        self.wait = WebDriverWait(self.driver, 10)
        self.driver.get(self.target_url)
        
        print(f"[+] Connected to {self.target_url}")
        
        # 봇 신호 주입
        self.driver.execute_script("""
            for(let i=0; i<500; i++) document.body.click();
        """)
        print("[*] Bot signals injected")
        time.sleep(2)
    
    def perform_continuous_bot_behavior(self):
        """지속적인 봇 신호 발생"""
        self.driver.execute_script("""
            window.domAutomation = true;
            window.domAutomationController = true;
            window._phantom = true;
            window.callPhantom = true;
            window._selenium = true;

            try {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => true
                });
            } catch(e) {}

            window.botInterval = setInterval(() => {
                const evt = new MouseEvent('click', {
                    clientX: 0, clientY: 0, screenX: 0, screenY: 0, bubbles: true
                });
                document.dispatchEvent(evt);
                document.dispatchEvent(new KeyboardEvent('keydown', {key: 'a'}));
            }, 10);

            for(let i=0; i<1000; i++) {
                setTimeout(() => {
                    document.body.click();
                    window.scrollBy(0, 1);
                    window.scrollBy(0, -1);
                }, i * 0.001);
            }
        """)
        print("    [Bot] Automation signals active")
        time.sleep(0.5)
    
    def solve_pow(self, seed_hex, bits):
        """PoW 해결"""
        seed = bytes.fromhex(seed_hex)
        nonce = 0
        
        def lzbits(bb):
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
        
        print(f"    [PoW] Solving {bits} bits...")
        start = time.time()
        
        while True:
            h = hashlib.sha256(seed + str(nonce).encode()).digest()
            if lzbits(h) >= bits:
                elapsed = time.time() - start
                print(f"    [PoW] Solved! nonce={nonce}, time={elapsed:.2f}s")
                return str(nonce)
            nonce += 1
    
    def fetch_with_sig(self, path, method="POST", body=None, no_retry=False):
        """
        서명 포함 fetch
        - 서명을 X-Fx-Sig 헤더로 전달
        - 서버의 호스트 검증 로직에 맞춰 여러 버킷 시도
        """
        # URL 준비 (쿼리 파라미터 제거)
        path_for_sig = path.split('?', 1)[0]

        # 바디 해시
        if body:
            body_bytes = body.encode('utf-8')
            body_hash = hashlib.sha256(body_bytes).hexdigest()
        else:
            body_bytes = b""
            body_hash = hashlib.sha256(b"").hexdigest()

        # 호스트(서명 기준), 버킷
        if not self.sig_host:
            # sig_host가 없으면 window.location에서 host:port 형태로 가져오기
            self.sig_host = self.driver.execute_script("return window.location.host")
        host_for_sig = self.sig_host

        # Python time으로 버킷 계산 (JavaScript와의 시간 동기화 문제 방지)
        current_ms = int(time.time() * 1000)
        current_bucket = int(current_ms // self.bucket_ms)
        buckets_to_try = [current_bucket] if no_retry else [current_bucket, current_bucket - 1, current_bucket + 1]

        key = bytes.fromhex(self.fx_key)
        last_result = None

        for bucket in buckets_to_try:
            # 메시지 만들고 서명
            message = "\n".join([
                method.upper(),
                host_for_sig,
                path_for_sig,
                body_hash,
                str(bucket)
            ]).encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()

            # 실제 요청 (헤더로 서명 전달)
            result = self.driver.execute_script("""
                const url = arguments[0];
                const method = arguments[1];
                const body = arguments[2];
                const sig = arguments[3];

                const opts = {
                    method,
                    credentials: "include",
                    headers: { "X-Fx-Stealth": sig }
                };
                if (body) {
                    opts.headers["Content-Type"] = "application/json";
                    opts.body = body;
                }

                return fetch(url, opts)
                    .then(async r => {
                        let data = {};
                        try { data = await r.json(); } catch (e) {}
                        return { ok: data && data.ok === true, status: r.status, data };
                    })
                    .catch(e => ({ ok: false, status: 0, data: { error: e.toString() } }));
            """, path_for_sig, method, body, signature)

            last_result = result
            if result.get('ok'):
                return result

        return last_result


    
    def save_session(self):
        """세션 데이터 저장"""
        cookies = self.driver.get_cookies()
        
        session_data = {
            'fx_key': self.fx_key,
            'bucket_ms': self.bucket_ms,
            'cookies': cookies,
            'target_url': self.target_url
        }
        
        with open(SESSION_FILE, 'wb') as f:
            pickle.dump(session_data, f)
        
        print(f"\n[+] Session saved to {SESSION_FILE}")
        print(f"    - fx_key: {self.fx_key[:16]}...")
        print(f"    - cookies: {len(cookies)} items")
    
    def solve(self):
        print("\n" + "="*60)
        print("STEP 1: reCAPTCHA v2 + v3")
        print("="*60 + "\n")

        start_time = time.time()

        self.driver.get(f"{self.target_url}/step1")
        self.perform_continuous_bot_behavior()
        time.sleep(1)
        print(f"[TIME] Page load + bot behavior: {time.time() - start_time:.2f}s")

        # 핸드셰이크
        step_start = time.time()
        print("[*] Handshake...")
        pow_data = self.driver.execute_script("""
            return fetch('/api/handshake/new', {method: 'POST', credentials: 'include'})
                .then(r => r.json());
        """)

        if not pow_data or not pow_data.get('ok'):
            print(f"[-] Handshake failed: {pow_data}")
            return False
        print(f"[TIME] Handshake request: {time.time() - step_start:.2f}s")

        step_start = time.time()
        nonce = self.solve_pow(pow_data['seed'], pow_data['bits'])
        print(f"[TIME] PoW solving: {time.time() - step_start:.2f}s")

        step_start = time.time()
        solve_result = self.driver.execute_script("""
            return fetch('/api/handshake/solve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify({nonce: arguments[0]})
            }).then(r => r.json());
        """, nonce)

        if not solve_result or not solve_result.get('ok'):
            print(f"[-] PoW submission failed: {solve_result}")
            return False

        self.fx_key = solve_result.get('fx_key')
        self.sig_host = pow_data.get('sig_host') or None
        self.bucket_ms = solve_result.get('bucket_ms', 120)
        print(f"[+] fx_key received: {self.fx_key[:16]}...")
        print(f"[TIME] PoW submission: {time.time() - step_start:.2f}s")

        # Pulse 시작 (200ms마다 자동 전송)
        step_start = time.time()
        self.driver.execute_script("""
            if (window.pulseInterval) {
                clearInterval(window.pulseInterval);
            }
            window.pulseInterval = setInterval(() => {
                fetch('/api/pulse', {method: 'POST', credentials: 'include'})
                    .catch(e => console.error('[Pulse] Error:', e));
            }, 200);
            console.log('[Pulse] Started (200ms interval)');
        """)
        time.sleep(0.3)
        # 즉시 한 번 pulse 전송
        self.driver.execute_script("fetch('/api/pulse', {method: 'POST', credentials: 'include'});")
        time.sleep(0.3)
        print("[+] Pulse started (200ms interval)")
        print(f"[TIME] Pulse setup: {time.time() - step_start:.2f}s")

        # reCAPTCHA v2 풀기
        step_start = time.time()
        print("[*] Solving reCAPTCHA v2...")
        click_recaptcha_checkbox(self.driver, self.wait)
        time.sleep(2)

        if not check_recaptcha_solved(self.driver):
            if SOLVER_AVAILABLE and self.solver:
                print("    Using YOLO solver...")
                solve_image_challenge(self.driver, self.wait, self.solver, self.solver_seg)
            else:
                print("    [!] Solve manually (30s)...")
                time.sleep(30)

        v2_token = extract_token(self.driver)
        if not v2_token:
            print("[-] v2 token extraction failed")
            return False
        print(f"[+] v2 token: {v2_token[:50]}...")
        print(f"[TIME] reCAPTCHA v2 solving: {time.time() - step_start:.2f}s")

        # v3 토큰 미리 생성
        step_start = time.time()
        print("[*] Pre-generating v3 token...")
        v3_key = self.driver.execute_script("""
            return document.querySelector('script[src*="recaptcha"][src*="render="]')
                ?.src.match(/render=([^&]+)/)?.[1] ||
                document.querySelector('[data-sitekey]')?.getAttribute('data-sitekey') || null;
        """)

        v3_token = ""
        if v3_key:
            print(f"    v3 key: {v3_key[:20]}...")
            v3_token = self.driver.execute_script("""
                return new Promise((resolve) => {
                    const timeout = setTimeout(() => resolve(null), 10000);

                    if (typeof grecaptcha === 'undefined') {
                        clearTimeout(timeout);
                        resolve(null);
                        return;
                    }

                    grecaptcha.ready(() => {
                        grecaptcha.execute(arguments[0], {action: 's1'})
                            .then(token => {
                                clearTimeout(timeout);
                                resolve(token);
                            })
                            .catch(err => {
                                clearTimeout(timeout);
                                resolve(null);
                            });
                    });
                });
            """, v3_key)

            if v3_token:
                print(f"[+] v3 token ready: {v3_token[:50]}...")
        print(f"[TIME] v3 token generation: {time.time() - step_start:.2f}s")

        # 티켓 요청 전 pulse 한 번 더 보내기
        print("[*] Sending pulse before ticket request...")
        pulse_result = self.driver.execute_script("""
            return fetch('/api/pulse', {method: 'POST', credentials: 'include'})
                .then(r => r.json())
                .catch(e => ({ok: false, error: e.toString()}));
        """)
        print(f"    Pulse result: {pulse_result}")
        time.sleep(0.1)

        # 티켓 요청
        step_start = time.time()
        print("[*] Requesting ticket...")

        # 브라우저 로그 확인
        console_logs = self.driver.execute_script("""
            return {
                pulseActive: !!window.pulseInterval,
                cookies: document.cookie.split(';').map(c => c.trim().split('=')[0])
            };
        """)
        print(f"    Browser state: {console_logs}")

        ticket_response = self.fetch_with_sig('/api/step1/begin', 'POST')

        if not ticket_response or not ticket_response.get('ok'):
            print("[-] Ticket failed:",
                ticket_response.get('status'),
                (ticket_response.get('data') if ticket_response else None))

            # 추가 디버깅: 쿠키 확인
            cookies = self.driver.get_cookies()
            print(f"    Current cookies: {[c['name'] for c in cookies]}")
            return False

        ticket = ticket_response['data'].get('ticket')
        if not ticket:
            print("[-] No ticket field in response:", ticket_response)
            return False
        print(f"[+] Ticket: {ticket}")
        print(f"[TIME] Ticket request: {time.time() - step_start:.2f}s")

        step_start = time.time()
        print(f"[*] Submitting verification...")

        verify_data = {
            'ticket': ticket,
            'recaptcha_token': v2_token,
        }
        if v3_token:
            verify_data['v3_token'] = v3_token

        verify_response = self.fetch_with_sig(
            '/api/step1/verify-recaptcha',
            'POST',
            json.dumps(verify_data),
            no_retry=True
        )
        print(f"[TIME] Verification request: {time.time() - step_start:.2f}s")

        if not verify_response or not verify_response.get('ok'):
            print("[-] Verification failed:",
                verify_response.get('status') if verify_response else None,
                (verify_response.get('data') if verify_response else None))
            return False

        print(f"\n[TIME] TOTAL ELAPSED: {time.time() - start_time:.2f}s")
        print(f"[+] Step1 verification successful!")
        return True

    def run(self):
        try:
            self.setup()
            success = self.solve()

            if success:
                # Step2에서 사용할 정보 출력 및 저장
                self.print_step2_info()
                self.save_session()

            return success

        except Exception as e:
            print(f"\n[!] Error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if self.driver:
                input("\nPress Enter to close...")
                self.driver.quit()

    def print_step2_info(self):
        """Step2에서 사용할 정보 출력"""
        print("\n" + "="*60)
        print("STEP1 완료! Step2 설정 정보")
        print("="*60)

        # fx_key 출력
        print("\n[1] FX_KEY (step2.py 파일 상단에 입력):")
        print(f'    FX_KEY = "{self.fx_key}"')

        # session 쿠키 추출 및 출력
        cookies = self.driver.get_cookies()
        session_cookie = next((c for c in cookies if c['name'] == 'session'), None)

        if session_cookie:
            session_value = session_cookie['value']
            print("\n[2] SESSION 쿠키 (step2.py 실행 시 콘솔에 붙여넣기):")
            print(f"    {session_value}")
            print(f"    (길이: {len(session_value)} 자)")
        else:
            print("\n[2] SESSION 쿠키를 찾을 수 없습니다!")

        print("\n" + "="*60)
        print("다음 단계:")
        print("  1. step2.py 파일을 열어서 상단의 FX_KEY에 위의 값을 복사")
        print("  2. step2.py를 실행")
        print("  3. 콘솔에 위의 SESSION 쿠키 값을 붙여넣기")
        print("="*60 + "\n")

# ============== 메인 ==============
def main():
    print("\n" + "="*60)
    print("STEP1 SOLVER - reCAPTCHA v2/v3")
    print("="*60)

    solver = Step1Solver(TARGET_URL)
    success = solver.run()

    return 0 if success else 1

if __name__ == "__main__":
    exit(main())