"""
预约核心模块：登录 + 页面抓取 + 提交预约
使用 CaptchaSolver 统一处理验证码
"""
import json
import time
import re
import random
import logging
import datetime
from typing import Tuple, Optional, List

from curl_cffi import requests
from utils.encrypt import AES_Encrypt, verify_param
from utils.captcha import CaptchaSolver
from utils.playwright_handler import PlaywrightCaptchaHandler
from utils.fingerprint import random_ua, build_sec_ch_ua, random_delay


def get_date(day_offset: int = 0) -> str:
    today = datetime.datetime.now().date()
    offset_day = today + datetime.timedelta(days=day_offset)
    return offset_day.strftime("%Y-%m-%d")


class SeatReserver:
    """超星座位预约器"""

    # ===================== URL 常量 =====================
    LOGIN_PAGE = "https://passport2.chaoxing.com/mlogin?loginType=1&newversion=true&fid="
    LOGIN_URL = "https://passport2.chaoxing.com/fanyalogin"
    SEAT_PAGE = "https://office.chaoxing.com/front/third/apps/seat/code?id={}&seatNum={}"
    SUBMIT_URL = "https://office.chaoxing.com/data/apps/seat/submit"
    CAPTCHA_TYPE_URL = "https://office.chaoxing.com/data/apps/seat/captcha/type"
    ROOM_LIST_URL = ("https://office.chaoxing.com/data/apps/seat/room/list"
                     "?cpage=1&pageSize=100&firstLevelName=&secondLevelName="
                     "&thirdLevelName=&deptIdEnc={}")

    # ===================== 验证码类型查询 =====================
    def _get_captcha_type(self) -> str:
        """
        向服务器查询当前需要什么类型的验证码（真实浏览器就是这样做的）
        返回: "slide" / "textclick" / "none"
        captchaType 映射: 0=slide, 1=textclick
        """
        try:
            resp = self.session.post(
                self.CAPTCHA_TYPE_URL,
                data={"appType": "0", "appId": "22640"},
                headers={**self.login_headers, "Referer": "https://office.chaoxing.com/"},
            )
            data = resp.json()
            if not data.get("success"):
                logging.warning(f"查询验证码类型失败: {data}")
                return "slide"  # fallback

            ct = data.get("data", {})
            captcha_open = ct.get("captchaOpen", True)
            captcha_type = ct.get("captchaType", 0)

            if not captcha_open:
                logging.info("服务器返回: 无需验证码")
                return "none"

            type_map = {0: "slide", 1: "textclick"}
            result = type_map.get(captcha_type, "slide")
            logging.info(f"服务器指定验证码类型: captchaType={captcha_type} → {result}")
            return result

        except Exception as e:
            logging.warning(f"查询验证码类型异常: {e}, fallback slide")
            return "slide"
    # token 格式: 32位hex_数字，后缀不固定，从 submit_enc input 或页面全局变量提取
    TOKEN_PAT = re.compile(r"([a-f0-9]{32}_\d+)")
    VALUE_PAT = re.compile(r'value="(.*?)"')
    SUBMIT_ENC_PAT = re.compile(r'id="submit_enc"\s+value="([^"]+)"')
    FIDENC_PAT = re.compile(r"fidEnc\s*=\s*'([^']+)'")

    def __init__(
        self,
        sleep_time: float = 0.5,
        max_attempt: int = 5,
        captcha_type: str = "slide",
        reserve_next_day: bool = False,
        use_playwright: bool = True,
        cjy_user: str = "",
        cjy_pass: str = "",
        cjy_soft_id: str = "",
    ):
        self.sleep_time = sleep_time
        self.max_attempt = max_attempt
        self.captcha_type = captcha_type  # "slide" / "text" / "auto" / "none"
        self.reserve_next_day = reserve_next_day
        self.use_playwright = use_playwright

        # 随机选择 UA 版本（每次实例化不同，避免固定指纹）
        ver, ua = random_ua()

        # 创建带指纹伪装的 session
        self.session = requests.Session(impersonate=f"chrome{ver}")

        # 请求头（统一使用桌面端 UA，消除 iPhone/Windows 矛盾）
        sec_ch = build_sec_ch_ua(ver)
        self.captcha_headers = {
            "Referer": "https://office.chaoxing.com/",
            "Host": "captcha.chaoxing.com",
            "Sec-Ch-Ua": sec_ch,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "User-Agent": ua,
        }

        self.login_headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Sec-Ch-Ua": sec_ch,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "User-Agent": ua,
        }

        # 验证码解决器（API模式）
        self.captcha = CaptchaSolver(self.session, self.captcha_headers)

        # Playwright 验证码处理器
        self.pw_handler = PlaywrightCaptchaHandler(
            chaojiying_user=cjy_user,
            chaojiying_pass=cjy_pass,
            chaojiying_soft_id=cjy_soft_id,
        ) if use_playwright else None

        # 状态
        self.logged_in = False
        self.username = ""

    # ===================== 登录流程 =====================
    def get_login_status(self):
        """获取登录页面的 cookie"""
        self.session.headers = self.login_headers
        resp = self.session.get(self.LOGIN_PAGE)
        logging.info(f"获取登录页, status={resp.status_code}")

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        登录超星账号
        返回: (success, message)
        """
        self.username = username

        uname_enc = AES_Encrypt(username)
        pwd_enc = AES_Encrypt(password)

        # 使用通用 office.chaoxing.com 首页作为 refer，不再指向特定座位
        params = {
            "fid": -1,
            "uname": uname_enc,
            "password": pwd_enc,
            "refer": "http%3A%2F%2Foffice.chaoxing.com%2F",
            "t": True,
        }

        resp = self.session.post(self.LOGIN_URL, params=params, headers=self.login_headers)
        result = resp.json()

        if result.get("status"):
            self.logged_in = True
            logging.info(f"登录成功: {username}")
            return True, ""
        else:
            msg = result.get("msg2", "未知错误")
            logging.warning(f"登录失败: {username}, 原因: {msg}")
            return False, msg

    # ===================== 页面 Token 获取 =====================
    def _get_page_token(self, roomid: str, seatid: str) -> Tuple[str, str]:
        """获取座位页面的 token 和 algorithm value"""
        url = self.SEAT_PAGE.format(roomid, seatid)
        resp = self.session.get(url)

        # 处理可能的重定向（登录态失效）
        if "passport" in resp.url and "login" in resp.url:
            logging.warning("登录态失效，需要重新登录")
            return "", ""

        html = resp.content.decode("utf-8", errors="replace")
        logging.info(f"页面URL(可能重定向): {resp.url}, 页面大小: {len(html)}")

        # 检测页面类型
        if "codemyselfuse" in resp.url:
            logging.info("页面类型: 本人使用中/座位状态页")
        elif "seat/code" in resp.url:
            logging.info("页面类型: 预约页面")
        else:
            logging.info(f"页面类型: 未知 ({resp.url})")

        token = ""
        value = ""

        # 方式1: 优先从 submit_enc input 提取（最可靠）
        enc_match = self.SUBMIT_ENC_PAT.search(html)
        if enc_match:
            token = enc_match.group(1)
            logging.info(f"从 submit_enc 提取token: {token[:30]}...")

        # 方式2: 用通用正则匹配
        if not token:
            tokens = self.TOKEN_PAT.findall(html)
            if tokens:
                token = tokens[0]
                logging.info(f"从正则提取token: {token[:30]}...")

        if not token:
            logging.error(f"未找到token! URL={resp.url}")
            # dump 前500字符帮助调试
            logging.debug(f"HTML开头: {html[:500]}")
            return "", ""

        # 找 algorithm value (submit_enc 的 value 可复用)
        if not value:
            values = self.VALUE_PAT.findall(html)
            value = values[0] if values else token  # fallback: 用 token 本身

        # 提取 fidEnc（页面全局变量，部分API需要）
        fid_match = self.FIDENC_PAT.search(html)
        if fid_match:
            logging.info(f"fidEnc: {fid_match.group(1)}")

        logging.info(f"获取token成功: {token[:20]}..., value: {value[:20]}...")
        return token, value

    # ===================== 提交预约 =====================
    def _do_submit(self, roomid: str, seatid: str, times: List[str],
                   token: str, value: str, captcha_validate: str,
                   action: bool = False, wy_token: str = "") -> bool:
        """执行一次预约提交"""
        delta_day = 1 if self.reserve_next_day else 0
        if action:
            delta_day += 1  # GitHub Actions 时区补偿
        day = (datetime.date.today() + datetime.timedelta(days=delta_day)).isoformat()

        params = {
            "roomId": roomid,
            "startTime": times[0],
            "endTime": times[1],
            "day": day,
            "seatNum": seatid,
            "captcha": captcha_validate,
            "token": token,
            "type": "1",
            "verifyData": "1",
        }

        # 如果有 wyToken（Playwright 从页面提取的易盾风控 token），加入参数
        # 注意：这会改变 enc 的计算结果，但服务端开启风控时也会做同样的校验
        if wy_token:
            params["wyToken"] = wy_token
            logging.info(f"携带 wyToken: {wy_token[:20]}...")

        params["enc"] = verify_param(params, value)

        logging.info(f"提交预约: room={roomid} seat={seatid} day={day} time={times[0]}~{times[1]}")
        resp = self.session.post(self.SUBMIT_URL, params=params)
        result = resp.json()
        logging.info(f"提交结果: {json.dumps(result, ensure_ascii=False)}")

        return result.get("success", False)

    # ===================== 主流程：提交一个座位 =====================
    def submit_one_seat(self, roomid: str, seatid: str,
                        times: List[str], action: bool = False) -> bool:
        """
        对单个座位执行完整的预约流程（含重试）
        返回: 是否成功
        """
        for attempt in range(1, self.max_attempt + 1):
            logging.info(f"--- 座位{seatid} 第{attempt}/{self.max_attempt}次尝试 ---")

            wy_token = ""  # 风控 token，仅 Playwright 路径能获取

            if self.use_playwright and self.pw_handler:
                # ===== Playwright 路径：页面token + 验证码 + wyToken 一次搞定 =====
                pw_result = self.pw_handler.solve(
                    self.session.cookies, roomid, seatid, self.captcha_type
                )
                token = pw_result["page_token"]
                value = token  # value 复用 page_token
                validate = pw_result["validate"]
                wy_token = pw_result.get("wy_token", "")
                captcha_used = pw_result["captcha_type"]

                if not token:
                    logging.warning("[PW] 获取token失败，跳过本次尝试")
                    time.sleep(random_delay(0.8, 2.5))
                    continue

                if not validate:
                    logging.warning(f"[PW] 验证码解决失败 (类型={captcha_used})，跳过本次尝试")
                    time.sleep(random_delay(0.8, 2.5))
                    continue

                logging.info(f"[PW] token+验证码完成 (验证类型={captcha_used}, wyToken={'有' if wy_token else '无'})")

            else:
                # ===== API 路径 =====
                # 1. 获取页面 token
                token, value = self._get_page_token(roomid, seatid)
                if not token:
                    logging.warning("获取token失败，跳过本次尝试")
                    time.sleep(random_delay(0.8, 2.5))
                    continue

                # 2. 查询服务器要求的验证码类型（不要自己猜！）
                actual_captcha_type = self._get_captcha_type()

                # 3. 解决验证码
                seat_url = self.SEAT_PAGE.format(roomid, seatid)
                validate = ""
                for captcha_try in range(3):
                    validate = self.captcha.solve(actual_captcha_type, seat_ref=seat_url)
                    if validate:
                        break
                    logging.warning(f"验证码解决失败，重试 {captcha_try+1}/3")
                    time.sleep(random_delay(0.5, 1.5))

                if not validate:
                    logging.warning("验证码解决失败，跳过本次尝试")
                    time.sleep(random_delay(0.8, 2.5))
                    continue

            # 3. 提交预约
            success = self._do_submit(
                roomid, seatid, times,
                token=token, value=value,
                captcha_validate=validate,
                action=action,
                wy_token=wy_token,
            )

            if success:
                logging.info(f"预约成功! 座位{seatid}")
                return True

            # 失败则等待后重试（更自然的随机间隔）
            if attempt < self.max_attempt:
                wait = random_delay(0.8, 2.5)
                logging.info(f"预约失败，等待 {wait:.1f}s 重试...")
                time.sleep(wait)

        logging.warning(f"座位{seatid} 达到最大尝试次数({self.max_attempt})，放弃")
        return False

    def submit(self, times: List[str], roomid: str,
               seatids: List[str], action: bool = False) -> bool:
        """
        提交所有指定座位的预约
        有一个成功即返回 True
        """
        for seatid in seatids:
            time.sleep(random_delay(0.5, 2.0))
            if self.submit_one_seat(roomid, seatid, times, action):
                return True
        return False

    # ===================== 辅助功能 =====================
    def get_room_list(self, dept_enc: str) -> list:
        """根据 deptIdEnc 获取可选房间列表"""
        url = self.ROOM_LIST_URL.format(dept_enc)
        resp = self.session.get(url)
        data = resp.json()
        rooms = data.get("data", {}).get("seatRoomList", [])
        for room in rooms:
            print(f"  {room['firstLevelName']}-{room['secondLevelName']}-{room['thirdLevelName']} id={room['id']}")
        return rooms


# ===================== 向后兼容的包装 =====================
# 让 main.py 中原有的 import 仍可工作
class reserve(SeatReserver):
    """向后兼容的别名"""
    pass
