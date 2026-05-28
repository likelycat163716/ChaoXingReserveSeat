"""
基于 Playwright 的验证码处理模块
使用真实浏览器环境解决超星验证码（滑块/文字点选/无需验证）

核心思路:
- curl_cffi 负责登录
- Playwright 用登录 cookie 打开座位页面
- 在页面 JS 上下文中调用验证码 API（保证 referer/origin 正确）
- 滑块用 OpenCV，文字点选用超级鹰，无验证码直接跳过
"""

import json
import time
import random
import logging
import base64
import re
from typing import Tuple, Optional, List
from hashlib import md5
from io import BytesIO

import numpy as np
import cv2
import urllib.request
import urllib.parse

from utils.encrypt import generate_captcha_key, generate_iv
from utils.fingerprint import random_ua, random_delay

# ===================== 常量 =====================
CAPTCHA_ID = "42sxgHoTPTKbt0uZxPJ7ssOvtXr3ZgZ1"
CAPTCHA_VERSION = "1.1.20"
CAPTCHA_API_IMAGE = "https://captcha.chaoxing.com/captcha/get/verification/image"
CAPTCHA_API_CHECK = "https://captcha.chaoxing.com/captcha/check/verification/result"

# ===================== JS 辅助函数 =====================
# 在页面上下文中调用验证码 API 的 JS 代码

FETCH_CAPTCHA_JS = """
async (captchaType, captchaKey, token, referer, iv) => {
    const p = new URLSearchParams({
        captchaId: '{captcha_id}',
        type: captchaType,
        version: '{version}',
        captchaKey: captchaKey,
        token: token,
        referer: referer || window.location.href,
        iv: iv,
        _: Date.now(),
        d: 'a',
        b: 'a'
    });
    const url = '{api_image}?' + p.toString();
    const resp = await fetch(url, { credentials: 'include' });
    const text = await resp.text();
    // 去掉 callback 包装（兼容多种格式）
    const json = JSON.parse(text.replace(/^[^(]*\\(/, '').replace(/\\)$/, ''));
    return json;
}
""".replace('{captcha_id}', CAPTCHA_ID).replace('{version}', CAPTCHA_VERSION).replace('{api_image}', CAPTCHA_API_IMAGE)

VERIFY_CAPTCHA_JS = """
async (captchaType, captchaToken, textClickArr, coordinate, slideX, iv) => {
    let tca = textClickArr || [];
    let coord = coordinate || [];
    if (captchaType === 'slide') {
        tca = slideX !== null ? [{'x': slideX}] : [];
        coord = [];
    }
    const p = new URLSearchParams({
        captchaId: '{captcha_id}',
        type: captchaType,
        token: captchaToken,
        textClickArr: JSON.stringify(tca),
        coordinate: JSON.stringify(coord),
        runEnv: '10',
        version: '{version}',
        t: 'a',
        iv: iv || '',
        _: Date.now()
    });
    const url = '{api_check}?' + p.toString();
    const resp = await fetch(url, { credentials: 'include' });
    const text = await resp.text();
    const json = JSON.parse(text.replace(/^[^(]*\\(/, '').replace(/\\)$/, ''));
    return json;
}
""".replace('{captcha_id}', CAPTCHA_ID).replace('{version}', CAPTCHA_VERSION).replace('{api_check}', CAPTCHA_API_CHECK)

DOWNLOAD_IMG_JS = """
async (url) => {
    const resp = await fetch(url, { credentials: 'include' });
    const blob = await resp.blob();
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
    });
}
"""


class PlaywrightCaptchaHandler:
    """使用 Playwright 解决超星预约验证码"""

    PAGE_TOKEN_PAT = re.compile(r'id="submit_enc"\s+value="([^"]+)"')
    FIDENC_PAT = re.compile(r"fidEnc\s*=\s*'([^']+)'")

    # 尝试从页面抓取 wyToken（网易易盾风控 token）
    # 如果管理员后台开了风险校验，这个 token 会被后端强制校验
    EXTRACT_WYTOKEN_JS = """
    (() => {
        // 方式1: window 全局变量
        if (window.__wyToken) return window.__wyToken;
        if (window._wyToken) return window._wyToken;
        if (window.wyToken) return window.wyToken;
        // 方式2: 从 YiDunProtector 实例获取（网易易盾常见模式）
        if (window._fm_opt && window._fm_opt.getToken) {
            try { return window._fm_opt.getToken(); } catch(e) {}
        }
        // 方式3: 查找页面中所有可能的 token 存储
        for (const key of Object.keys(window)) {
            if (key.toLowerCase().includes('yidun') || key.toLowerCase().includes('token')) {
                const val = window[key];
                if (typeof val === 'string' && val.length > 10 && val.length < 500) {
                    return val;
                }
            }
        }
        // 方式4: 从 sessionStorage
        try { const t = sessionStorage.getItem('wyToken'); if (t) return t; } catch(e) {}
        try { const t2 = sessionStorage.getItem('_yidun_token'); if (t2) return t2; } catch(e) {}
        // 方式5: 拦截 WyRiskCheckSubmit 调用（最可靠但需要等触发）
        return '';
    })()
    """

    def __init__(
        self,
        chaojiying_user: str = "",
        chaojiying_pass: str = "",
        chaojiying_soft_id: str = "",
    ):
        self.cjy_user = chaojiying_user
        self.cjy_pass = chaojiying_pass
        self.cjy_soft_id = chaojiying_soft_id

    # ===================== Cookie 转换 =====================
    @staticmethod
    def convert_cookies(session_cookies) -> list:
        """
        将 curl_cffi 的 cookies 转为 Playwright 格式
        session_cookies: curl_cffi session.cookies 对象 或 dict
        返回: [{"name": str, "value": str, "domain": str, "path": str}, ...]
        """
        pw_cookies = []
        try:
            cookie_dict = session_cookies.get_dict() if hasattr(session_cookies, "get_dict") else dict(session_cookies)
        except Exception:
            cookie_dict = {}
            for c in session_cookies:
                try:
                    cookie_dict[c.name] = c.value
                except Exception:
                    pass

        for name, value in cookie_dict.items():
            pw_cookies.append({
                "name": name,
                "value": str(value),
                "domain": ".chaoxing.com",
                "path": "/",
            })
        return pw_cookies

    # ===================== 主入口 =====================
    def solve(
        self,
        session_cookies,
        roomid: str,
        seatid: str,
        captcha_type: str = "auto",
    ) -> dict:
        """
        Playwright 解决验证码

        参数:
            session_cookies: curl_cffi 登录后的 session.cookies
            roomid, seatid: 房间/座位ID
            captcha_type: "slide" / "text" / "auto" / "none"

        返回:
            {"validate": str, "page_token": str, "fid_enc": str,
             "success": bool, "captcha_type": str}
        """
        from playwright.sync_api import sync_playwright

        result = {
            "validate": "",
            "page_token": "",
            "fid_enc": "",
            "wy_token": "",       # 网易易盾风控 token
            "success": False,
            "captcha_type": "none",
        }

        pw_cookies = self.convert_cookies(session_cookies)
        if not pw_cookies:
            logging.error("[PW] cookie为空，可能未登录")
            return result

        _, pw_ua = random_ua()
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-infobars",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=pw_ua,
                locale="zh-CN",
                timezone_id="Asia/Shanghai",
            )
            # 注入 stealth JS 隐藏 webdriver 标记
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                window.chrome = { runtime: {} };
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] });
            """)
            context.add_cookies(pw_cookies)
            page = context.new_page()

            try:
                # 1. 打开座位页面
                url = f"https://office.chaoxing.com/front/third/apps/seat/code?id={roomid}&seatNum={seatid}"
                page.goto(url, wait_until="networkidle", timeout=30000)
                logging.info(f"[PW] 页面加载完成: {page.url}")

                # 检查登录态
                if "passport" in page.url and "login" in page.url:
                    logging.error("[PW] Cookie失效，需要重新登录")
                    browser.close()
                    return result

                # 2. 提取页面 token、fidEnc、wyToken
                html = page.content()
                page_token = self._extract_page_token(html)
                fid_enc = self._extract_fidenc(html)
                wy_token = self._extract_wytoken(page)
                result["page_token"] = page_token
                result["fid_enc"] = fid_enc
                result["wy_token"] = wy_token
                logging.info(f"[PW] page_token={page_token[:30] if page_token else 'EMPTY'}..., "
                             f"fidEnc={fid_enc}, wyToken={'有' if wy_token else '无'}")

                if not page_token:
                    logging.error("[PW] 未获取到页面token")
                    browser.close()
                    return result

                # 3. 解决验证码
                captcha_result = self._solve_captcha(page, captcha_type)
                result.update(captcha_result)

            except Exception as e:
                logging.error(f"[PW] 异常: {e}", exc_info=True)
            finally:
                browser.close()

        return result

    # ===================== 页面信息提取 =====================
    @staticmethod
    def _extract_page_token(html: str) -> str:
        m = PlaywrightCaptchaHandler.PAGE_TOKEN_PAT.search(html)
        return m.group(1) if m else ""

    @staticmethod
    def _extract_fidenc(html: str) -> str:
        m = PlaywrightCaptchaHandler.FIDENC_PAT.search(html)
        return m.group(1) if m else ""

    @staticmethod
    def _extract_wytoken(page) -> str:
        """尝试从页面 JS 上下文中提取网易易盾 wyToken"""
        try:
            token = page.evaluate(PlaywrightCaptchaHandler.EXTRACT_WYTOKEN_JS)
            return token if token else ""
        except Exception as e:
            logging.debug(f"[PW] 提取wyToken失败(可能未开启风控): {e}")
            return ""

    # ===================== 验证码解决策略 =====================
    def _solve_captcha(self, page, captcha_type: str) -> dict:
        """
        按优先级尝试验证码类型:
        auto 模式下随机顺序，避免固定 slide→text 模式
        """
        strategies = []
        if captcha_type == "slide":
            strategies = ["slide"]
        elif captcha_type == "text":
            strategies = ["text"]
        elif captcha_type == "none":
            strategies = ["none"]
        else:  # auto: 随机顺序
            if random.random() < 0.5:
                strategies = ["slide", "text", "none"]
            else:
                strategies = ["text", "slide", "none"]
            logging.info(f"[PW] auto 随机顺序: {strategies}")

        for stype in strategies:
            if stype == "slide":
                r = self._try_slide(page)
            elif stype == "text":
                r = self._try_text(page)
            else:
                r = self._try_none(page)

            if r["success"]:
                r["captcha_type"] = stype
                return r

        return {"validate": "", "success": False, "captcha_type": "none"}

    # ===================== 滑块 =====================
    def _try_slide(self, page) -> dict:
        """在页面上下文中尝试滑块验证码"""
        data = self._fetch_captcha(page, "slide")
        token = data.get("token", "")
        if not token:
            logging.info("[PW] 滑块: 获取失败")
            return {"validate": "", "success": False}

        vo = data.get("imageVerificationVo", {})
        bg_url = vo.get("shadeImage", "")
        tp_url = vo.get("cutoutImage", "")

        if not bg_url or not tp_url:
            logging.info("[PW] 滑块: 图片URL缺失")
            return {"validate": "", "success": False}

        # 下载图片
        bg_bytes = self._download_img(page, bg_url)
        tp_bytes = self._download_img(page, tp_url)
        if not bg_bytes or not tp_bytes:
            return {"validate": "", "success": False}

        # OpenCV 计算偏移
        x_offset = self._calc_slide_offset(bg_bytes, tp_bytes)
        x_offset += random.randint(-2, 2)
        logging.info(f"[PW] 滑块偏移: {x_offset}px")

        # 校验
        validate = self._verify_captcha(page, "slide", token, slide_x=x_offset,
                                        iv=data.get("_iv", ""))
        if validate:
            logging.info(f"[PW] 滑块通过! validate={validate[:20]}...")
        return {"validate": validate, "success": bool(validate)}

    # ===================== 文字点选 =====================
    def _try_text(self, page) -> dict:
        """在页面上下文中尝试文字点选验证码"""
        data = self._fetch_captcha(page, "text")
        token = data.get("token", "")
        if not token:
            logging.info("[PW] 文字点选: 获取失败，可能不需要")
            return {"validate": "", "success": False}

        vo = data.get("imageVerificationVo", {})
        img_url = vo.get("bgImage") or vo.get("shadeImage") or ""
        text_list = vo.get("textList") or vo.get("targetList") or ""

        if not img_url or not text_list:
            logging.warning(f"[PW] 文字点选数据不完整: img={bool(img_url)}, text={text_list}")
            return {"validate": "", "success": False}

        logging.info(f"[PW] 文字点选 - 需识别: {text_list}")

        # 下载图片
        img_bytes = self._download_img(page, img_url)
        if not img_bytes:
            return {"validate": "", "success": False}

        # 识别坐标
        coords = self._recognize_text_click(img_bytes, text_list)
        if not coords:
            logging.warning("[PW] 文字点选识别失败")
            return {"validate": "", "success": False}

        logging.info(f"[PW] 文字点选坐标: {coords}")

        # 校验
        text_click_arr = [{"x": c[0], "y": c[1]} for c in coords]
        validate = self._verify_captcha(
            page, "text", token,
            text_click_arr=text_click_arr,
            coordinate=[],
            iv=data.get("_iv", ""),
        )
        if validate:
            logging.info(f"[PW] 文字点选通过! validate={validate[:20]}...")
        return {"validate": validate, "success": bool(validate)}

    def _recognize_text_click(self, img_bytes: bytes, text_info: str) -> list:
        """
        识别文字点选坐标
        优先超级鹰，fallback 本地 PaddleOCR
        """
        if self.cjy_user and self.cjy_pass:
            coords = self._chaojiying_click(img_bytes, text_info)
            if coords:
                logging.info(f"[PW] 超级鹰坐标: {coords}")
                return coords
            logging.warning("[PW] 超级鹰返回空，尝试本地OCR")

        return self._local_ocr_click(img_bytes, text_info)

    # ===================== 无需验证 =====================
    def _try_none(self, page) -> dict:
        """无验证码场景"""
        logging.info("[PW] 无需验证码模式")
        return {"validate": "1", "success": True}

    # ===================== 验证码 API (通过页面JS调用) =====================
    def _fetch_captcha(self, page, captcha_type: str) -> dict:
        """在页面 JS 上下文中获取验证码"""
        timestamp = int(time.time() * 1000)
        captcha_key, token = generate_captcha_key(timestamp, captcha_type)
        iv = generate_iv(timestamp, captcha_type)

        try:
            data = page.evaluate(FETCH_CAPTCHA_JS, [captcha_type, captcha_key, token, None, iv])
        except Exception as e:
            logging.warning(f"[PW] fetch验证码异常: {e}")
            return {}
        # 把 iv 存到返回数据中
        data["_iv"] = iv
        logging.info(f"[PW] 获取验证码 type={captcha_type}, token={data.get('token','')[:20]}...")
        return data

    def _verify_captcha(self, page, captcha_type: str, captcha_token: str,
                        text_click_arr=None, coordinate=None, slide_x=None,
                        iv: str = "") -> str:
        """在页面 JS 上下文中提交验证答案，返回 validate token"""
        args = [captcha_type, captcha_token, text_click_arr, coordinate, slide_x, iv]

        try:
            data = page.evaluate(VERIFY_CAPTCHA_JS, args)
        except Exception as e:
            logging.warning(f"[PW] 验证提交异常: {e}")
            return ""

        if data.get("result") is False or data.get("success") is False:
            logging.warning(f"[PW] 验证失败: {data.get('msg', 'unknown')}")
            return ""

        try:
            return json.loads(data["extraData"])["validate"]
        except (KeyError, json.JSONDecodeError) as e:
            logging.warning(f"[PW] 解析validate失败: {e} data={json.dumps(data, ensure_ascii=False)[:200]}")
            return ""

    # ===================== 图片下载 (通过页面JS) =====================
    def _download_img(self, page, url: str) -> bytes:
        """在页面上下文中下载图片"""
        try:
            data_url = page.evaluate(DOWNLOAD_IMG_JS, [url])
            # data_url 格式: "data:image/png;base64,xxxx"
            _, encoded = data_url.split(",", 1)
            return base64.b64decode(encoded)
        except Exception as e:
            logging.warning(f"[PW] 下载图片失败 {url[:50]}: {e}")
            return b""

    # ===================== OpenCV 滑块计算 =====================
    @staticmethod
    def _calc_slide_offset(bg_bytes: bytes, tp_bytes: bytes) -> int:
        bg = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
        slider = cv2.imdecode(np.frombuffer(tp_bytes, np.uint8), cv2.IMREAD_UNCHANGED)
        if slider is None or bg is None or slider.shape[2] < 4:
            return random.randint(50, 200)

        mask = slider[:, :, 3]
        mask[mask != 0] = 255
        x, y, w, h = cv2.boundingRect(mask)
        tp = slider[y:y+h, x:x+w, :3]

        bg_edge = cv2.Canny(bg, 100, 200)
        tp_edge = cv2.Canny(tp, 100, 200)

        res = cv2.matchTemplate(
            cv2.cvtColor(bg_edge, cv2.COLOR_GRAY2RGB),
            cv2.cvtColor(tp_edge, cv2.COLOR_GRAY2RGB),
            cv2.TM_CCOEFF_NORMED,
        )
        _, _, _, max_loc = cv2.minMaxLoc(res)
        return max_loc[0]

    # ===================== 超级鹰 =====================
    def _chaojiying_click(self, img_bytes: bytes, text_info: str) -> list:
        """超级鹰 9005 文字点选识别"""
        params = {
            "user": self.cjy_user,
            "pass2": md5(self.cjy_pass.encode()).hexdigest(),
            "softid": self.cjy_soft_id,
            "codetype": "9005",
            "textcontent": text_info,
            "file_base64": base64.b64encode(img_bytes).decode(),
        }
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(
            "https://upload.chaojiying.net/Upload/Processing.php", data=data
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            result = resp.read().decode()
            logging.info(f"[PW] 超级鹰返回: {result}")
            return self._parse_chaojiying_result(result)
        except Exception as e:
            logging.warning(f"[PW] 超级鹰请求失败: {e}")
            return []

    @staticmethod
    def _parse_chaojiying_result(result: str) -> list:
        """解析超级鹰返回: 'pic_id|pic_str' 其中 pic_str 为 'x1,y1|x2,y2|...'"""
        parts = result.split("|")
        # parts[0] = pic_id, parts[1:] or parts[0] after | = coordinate strings
        coord_str = ""
        if len(parts) >= 2:
            coord_str = parts[1]
        else:
            # 可能整个结果就是坐标串
            coord_str = parts[0]

        coords = []
        # 分隔符可能是 | 或空格
        for token in coord_str.replace("|", " ").split():
            try:
                x_str, y_str = token.split(",")
                coords.append([int(x_str), int(y_str)])
            except (ValueError, TypeError):
                pass
        return coords

    # ===================== 本地 OCR =====================
    @staticmethod
    def _local_ocr_click(img_bytes: bytes, text_info: str) -> list:
        """本地 PaddleOCR 文字点选"""
        try:
            from paddleocr import PaddleOCR
        except ImportError:
            logging.warning("[PW] PaddleOCR未安装，无法本地识别文字点选")
            return []

        img = cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR)
        ocr = PaddleOCR(lang="ch")
        results = ocr.ocr(img, cls=False)

        if not results or not results[0]:
            return []

        coords = []
        need_chars = list(text_info.replace(" ", ""))

        for line in results[0]:
            text = line[1][0]
            box = line[0]
            cx = int(sum(p[0] for p in box) / 4)
            cy = int(sum(p[1] for p in box) / 4)

            for i, char in enumerate(need_chars):
                if char in text:
                    coords.append([cx, cy])
                    need_chars.pop(i)
                    break
            if not need_chars:
                break

        return coords
