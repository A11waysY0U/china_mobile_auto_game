import argparse
import base64
import logging
import random
import string
import time

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

from sensors_cookie import build_cookie_bundle

logger = logging.getLogger(__name__)

# --- 配置 ---
HOST = "wap.fj.10086.cn"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"

class MobileFujianClient:
    def __init__(self, screen_width: int = 390, screen_height: int = 844):
        self.session = requests.Session()
        self.session.headers.update(self._build_headers())

        # RSA 公钥 (用于登录)
        self.RSA_PUB_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClIxzD8Lp9FPldu6l3rWjPVWR18WbR6m8hwP+etrrJrahk9W5ACD5IueU9/1VwZR4uRCzxaQ5On9FSLAutxdAQoJHbi3MHFgRlcsAtUAuqj75AZgse4wQWZYfVpLZXAvduDYjq+MxIlVcCVSS3fDabgDUb0JW5v09Rs9IbKRddXQIDAQAB"

        # AES 配置 (用于游戏结算)
        self.AES_KEY = b"8cc70bf2a955c6bf"
        self.AES_IV = b"1692bc56e8b783f4"

        self._inject_sensors_cookies(screen_width, screen_height)

    # --- 工具方法 ---

    @staticmethod
    def _build_headers() -> dict:
        """补全浏览器风格请求头，降低被风控识别的概率"""
        return {
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": f"https://{HOST}",
            "Referer": f"https://{HOST}/bass-eliminateHappyH5/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"iOS"',
        }

    def _inject_sensors_cookies(self, screen_width: int, screen_height: int):
        """复用 sensors_cookie 的精确算法生成神策埋点 Cookie"""
        bundle = build_cookie_bundle(
            host=HOST,
            user_agent=UA,
            screen_width=screen_width,
            screen_height=screen_height,
            cross_subdomain=True,
            encrypt_cookie=True,
        )
        domain = bundle.cookie_domain or HOST
        self.session.cookies.set(
            bundle.new_user_cookie_name, bundle.new_user_cookie_value,
            domain=domain, path="/",
        )
        self.session.cookies.set(
            bundle.main_cookie_name, bundle.main_cookie_value,
            domain=domain, path="/",
        )
        logger.debug("sensors distinct_id: %s", bundle.distinct_id)

    # --- 加密工具方法 ---

    def _rsa_encrypt(self, text):
        """RSA 加密: 手机号/验证码 (PKCS1_v1_5 内部自动使用安全随机源)"""
        key = RSA.import_key(base64.b64decode(self.RSA_PUB_KEY))
        cipher = PKCS1_v1_5.new(key)
        return base64.b64encode(cipher.encrypt(text.encode())).decode()

    def _aes_encrypt(self, data_str):
        """AES-CBC 加密: 关卡/分数 (带9位随机前缀)"""
        cipher = AES.new(self.AES_KEY, AES.MODE_CBC, self.AES_IV)
        data_bytes = data_str.encode('utf-8')
        # 补位逻辑: 0 填充
        pad_len = 16 - (len(data_bytes) % 16)
        if pad_len != 16:
            data_bytes += b'\x00' * pad_len
        
        encrypted = cipher.encrypt(data_bytes)
        res_base64 = base64.b64encode(encrypted).decode('utf-8')
        prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=9))
        return prefix + res_base64

    # --- 请求封装 ---

    def _request(self, method: str, url: str, *, json=None, retries: int = 3, backoff: float = 1.0, **kwargs) -> dict:
        """统一请求封装：自动重试 + 指数退避 + 日志"""
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.request(method, url, json=json, timeout=20, **kwargs)
                return resp.json()
            except (requests.RequestException, ValueError) as exc:
                last_exc = exc
                logger.warning("请求 %s 失败(第 %d/%d 次): %s", url, attempt, retries, exc)
                if attempt < retries:
                    time.sleep(backoff * (2 ** (attempt - 1)))
        raise RuntimeError(f"请求 {url} 重试 {retries} 次仍失败: {last_exc}")

    # --- 业务接口方法 ---

    def page_init(self):
        """1. 获取初始 Authorization Token"""
        url = f"https://{HOST}/bass-applet-authServer/auth/pageInit"
        payload = {"scope": 0, "url": f"https://{HOST}/bass-eliminateHappyH5/", "appId": 0, "timestamp": int(time.time() * 1000)}
        resp = self._request("POST", url, json=payload)
        if resp.get("success"):
            self.session.headers["Authorization"] = f"Bearer {resp['data']['token']}"
            return True
        return False

    def send_sms(self, phone):
        """2. 发送短信验证码"""
        url = f"https://{HOST}/bass-applet-authServer/auth/sendSmsCode"
        payload = {"phone": self._rsa_encrypt(phone), "version": 2, "appId": 0, "timestamp": int(time.time() * 1000)}
        return self._request("POST", url, json=payload)

    def login(self, phone, code):
        """3. 短信登录获取正式 Token"""
        url = f"https://{HOST}/bass-applet-authServer/auth/loginBySms"
        payload = {"smsCode": self._rsa_encrypt(code), "phone": self._rsa_encrypt(phone), "version": 2, "appId": 0, "timestamp": int(time.time() * 1000)}
        resp = self._request("POST", url, json=payload)
        if resp.get("success"):
            token = resp['data']['token']
            self.session.headers["Authorization"] = f"Bearer {token}"
            logger.info("已获取 token: %s...%s", token[:8], token[-4:])
        return resp

    def submit_score(self, level, score):
        """4. 提交游戏分数 (使用 AES 加密)"""
        url = f"https://{HOST}/bass-commonAreaServer/H5Api/eliminate/playEnd"
        payload = {
            "gameLevel": self._aes_encrypt(str(level)),
            "isOld": True,
            "score": self._aes_encrypt(str(score)),
            "appId": 0,
            "timestamp": int(time.time() * 1000)
        }
        return self._request("POST", url, json=payload)

    def get_index_info(self):
        """获取 /eliminate/indexInfo 接口返回（用于读取当前 gameLevel）"""
        url = f"https://{HOST}/bass-commonAreaServer/H5Api/eliminate/indexInfo"
        try:
            return self._request("GET", url)
        except Exception as exc:
            return {"success": False, "msg": f"request failed: {exc}"}

# --- 完整业务流 ---

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="福建移动消消乐 H5 自动登录刷分脚本")
    parser.add_argument("--phone", required=True, help="登录手机号")
    parser.add_argument("--score", default="3", help="提交的分数 (默认 3)")
    parser.add_argument("--levels", type=int, default=5, help="要提交的关卡数量 (默认 5)")
    parser.add_argument("--delay", type=float, default=3.0, help="每次提交间隔秒数 (默认 3)")
    parser.add_argument("--screen-width", type=int, default=390, help="屏幕宽度，用于神策指纹 (默认 390)")
    parser.add_argument("--screen-height", type=int, default=844, help="屏幕高度，用于神策指纹 (默认 844)")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    client = MobileFujianClient(
        screen_width=args.screen_width,
        screen_height=args.screen_height,
    )

    # [流程] 初始化 -> 发短信 -> 登录 -> 刷分
    if not client.page_init():
        logger.error("环境初始化失败，请检查网络或接口是否变更")
        return
    logger.info("环境初始化成功")

    res = client.send_sms(args.phone)
    logger.info("验证码请求响应: %s", res)
    if not res.get("success"):
        logger.error("验证码发送失败: %s", res.get("msg", res))
        return

    sms_code = input("请输入验证码: ").strip()
    if not client.login(args.phone, sms_code).get("success"):
        logger.error("登录失败")
        return

    # 登录成功后，先调用 indexInfo 获取当前关卡
    info = client.get_index_info()
    if not info or not info.get("data") or info["data"].get("gameLevel") is None:
        logger.error("获取 indexInfo 失败: %s", info)
        return

    try:
        level = int(info["data"]["gameLevel"])
    except (TypeError, ValueError) as e:
        logger.error("无法解析 gameLevel: %s / %s", e, info)
        return

    for l in range(level, level + args.levels):
        logger.info("正在提交分数，关卡=%d ...", l)
        res = client.submit_score(level=l, score=args.score)
        if res.get("data"):
            prize = res["data"].get("prizeName")
            logger.info("获得奖品: %s", prize)
        else:
            logger.warning("未获得奖品: %s", res.get("msg", res))
        time.sleep(args.delay)


if __name__ == "__main__":
    main()