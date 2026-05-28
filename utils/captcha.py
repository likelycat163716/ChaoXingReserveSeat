"""
验证码模块：支持滑块(slide)和文字点选(text)两种类型
文字点选接入打码平台：图鉴(ttshitu.com)为主，超级鹰为备选
"""
import json
import time
import random
import logging
from hashlib import md5

import numpy as np
import cv2
from curl_cffi import requests

from utils.encrypt import generate_captcha_key, generate_iv
from utils.fingerprint import random_ua, random_callback

# ===================== 常量 =====================
CAPTCHA_ID = "42sxgHoTPTKbt0uZxPJ7ssOvtXr3ZgZ1"
CAPTCHA_API_IMAGE = "https://captcha.chaoxing.com/captcha/get/verification/image"
CAPTCHA_API_CHECK = "https://captcha.chaoxing.com/captcha/check/verification/result"
CAPTCHA_VERSION = "1.1.20"

# 打码平台配置（超级鹰）
CHAOJIYING_USER = ""   # 超级鹰用户名
CHAOJIYING_PASS = ""   # 超级鹰密码
CHAOJIYING_SOFT_ID = ""  # 软件ID

# 打码平台配置（图鉴 ttshitu.com）
TTSHITU_USER = "256238771"      # 图鉴用户名
TTSHITU_PASS = "Qwqsqwq1"      # 图鉴密码
TTSHITU_TYPEID = "21"  # 坐标点选题 typeid（已验证）


class CaptchaSolver:
    """统一的验证码解决器"""

    def __init__(self, session: requests.Session, headers: dict):
        self.session = session
        self.headers = headers

    # ===================== 获取验证码 =====================
    def _fetch_captcha(self, captcha_type: str = "slide",
                       seat_ref: str = "") -> dict:
        """
        从超星服务器获取验证码数据
        使用随机 callback 格式和动态 UA，避免固定指纹
        """
        timestamp = int(time.time() * 1000)
        captcha_key, token = generate_captcha_key(timestamp, captcha_type)
        iv = generate_iv(timestamp, captcha_type)
        referer = seat_ref or "https://office.chaoxing.com/front/third/apps/seat/code"
        callback = random_callback()

        params = {
            "callback": callback,
            "captchaId": CAPTCHA_ID,
            "type": captcha_type,
            "version": CAPTCHA_VERSION,
            "captchaKey": captcha_key,
            "token": token,
            "referer": referer,
            "iv": iv,
            "_": timestamp,
        }

        # 每次请求使用动态 UA
        ver, ua = random_ua()
        hdrs = dict(self.headers)
        hdrs["Referer"] = referer
        hdrs["Origin"] = "https://office.chaoxing.com"
        hdrs["User-Agent"] = ua
        hdrs["Sec-Ch-Ua"] = f'"Google Chrome";v="{ver}", "Chromium";v="{ver}", "Not.A/Brand";v="24"'

        resp = self.session.get(CAPTCHA_API_IMAGE, params=params, headers=hdrs)
        text = resp.text
        # 去掉 JSONP 包装，兼容多种 callback 格式
        try:
            # 通用 JSONP 解析：去掉 callback( 前缀和末尾 )
            result = json.loads(text.replace(callback + "(", "").rstrip(")"))
        except json.JSONDecodeError:
            logging.error(f"验证码API返回异常: {text[:200]}")
            return {}
        # 把 iv 存到返回数据中，后续 verify 需要用同一个 iv
        result["_iv"] = iv
        logging.info(f"获取验证码 token={result.get('token','')[:20]}... type={captcha_type} iv={iv[:10]}...")
        return result

    # ===================== 验证码校验 =====================
    def _verify_captcha(self, captcha_type: str, captcha_token: str,
                        text_click_arr: list = None, coordinate: list = None,
                        slide_x: int = None, iv: str = "") -> str:
        """提交验证码答案，返回 validate token"""
        callback = random_callback()

        # 构建参数: textClickArr=坐标数组, coordinate=空(抓包确认)
        if captcha_type == "slide":
            text_click_data = json.dumps([{"x": slide_x or 0}])
        else:
            text_click_data = json.dumps(text_click_arr or [])

        params = {
            "callback": callback,
            "captchaId": CAPTCHA_ID,
            "type": captcha_type,
            "token": captcha_token,
            "textClickArr": text_click_data,
            "coordinate": json.dumps([]),
            "runEnv": "10",
            "version": CAPTCHA_VERSION,
            "t": "a",
            "iv": iv,
            "_": int(time.time() * 1000),
        }

        ver, ua = random_ua()
        hdrs = dict(self.headers)
        hdrs["Referer"] = "https://captcha.chaoxing.com/"
        hdrs["User-Agent"] = ua
        hdrs["Sec-Ch-Ua"] = f'"Google Chrome";v="{ver}", "Chromium";v="{ver}", "Not.A/Brand";v="24"'
        resp = self.session.get(CAPTCHA_API_CHECK, params=params, headers=hdrs)
        raw_text = resp.text
        logging.info(f"验证码校验原始响应 (前200): {raw_text[:200]}")
        text = raw_text.replace(callback + "(", "").replace(")", "")
        data = json.loads(text)
        logging.info(f"验证码校验结果: {json.dumps(data, ensure_ascii=False)[:200]}")

        if data.get("result") is False or data.get("success") is False:
            logging.warning(f"验证码校验失败: {data.get('msg', 'unknown')}")
            return ""

        try:
            return json.loads(data["extraData"])["validate"]
        except (KeyError, json.JSONDecodeError) as e:
            logging.warning(f"解析validate失败: {e}")
            return ""

    # ===================== 滑块验证码 =====================
    def solve_slide(self, seat_ref: str = "") -> str:
        """解决滑块验证码，返回 validate token"""
        data = self._fetch_captcha("slide", seat_ref=seat_ref)
        captcha_token = data.get("token", "")
        if not captcha_token:
            logging.warning("滑块: 获取验证码失败")
            return ""

        vo = data.get("imageVerificationVo", {})
        bg_url = vo.get("shadeImage", "")
        tp_url = vo.get("cutoutImage", "")

        if not bg_url or not tp_url:
            logging.warning("滑块: 图片URL缺失")
            return ""

        logging.info(f"滑块验证码 - bg: {bg_url[:60]}..., tp: {tp_url[:60]}...")
        x_offset = self._calc_slide_offset(bg_url, tp_url)
        # 偏移量宽容范围 ±2px，不加额外随机（CV 结果本身已有不精确性）
        logging.info(f"滑块偏移量: {x_offset}px")

        return self._verify_captcha("slide", captcha_token, slide_x=x_offset,
                                    iv=data.get("_iv", ""))

    def _calc_slide_offset(self, bg_url: str, tp_url: str) -> int:
        """用 OpenCV 计算滑块偏移量"""
        ver, ua = random_ua()
        c_headers = {
            "Referer": "https://office.chaoxing.com/",
            "Host": "captcha-b.chaoxing.com",
            "Sec-Ch-Ua": f'"Google Chrome";v="{ver}", "Chromium";v="{ver}"',
            "User-Agent": ua,
        }

        bg_data = self.session.get(bg_url, headers=c_headers).content
        tp_data = self.session.get(tp_url, headers=c_headers).content

        bg_img = cv2.imdecode(np.frombuffer(bg_data, np.uint8), cv2.IMREAD_COLOR)
        tp_img = self._cut_slide(tp_data)
        if tp_img is None:
            return random.randint(50, 200)

        bg_edge = cv2.Canny(bg_img, 100, 200)
        tp_edge = cv2.Canny(tp_img, 100, 200)
        res = cv2.matchTemplate(
            cv2.cvtColor(bg_edge, cv2.COLOR_GRAY2RGB),
            cv2.cvtColor(tp_edge, cv2.COLOR_GRAY2RGB),
            cv2.TM_CCOEFF_NORMED,
        )
        _, _, _, max_loc = cv2.minMaxLoc(res)
        return max_loc[0]

    @staticmethod
    def _cut_slide(slide_bytes: bytes):
        """裁剪滑块图片，去除透明区域"""
        slider_array = np.frombuffer(slide_bytes, np.uint8)
        slider_image = cv2.imdecode(slider_array, cv2.IMREAD_UNCHANGED)
        if slider_image is None or slider_image.shape[2] < 4:
            return None
        mask = slider_image[:, :, 3]
        mask[mask != 0] = 255
        x, y, w, h = cv2.boundingRect(mask)
        return slider_image[y:y + h, x:x + w, :3]

    # ===================== 文字点选验证码 =====================
    def solve_text_click(self, seat_ref: str = "") -> str:
        """
        解决文字点选验证码
        优先使用图鉴，再试超级鹰，fallback 到本地OCR
        """
        data = self._fetch_captcha("textclick", seat_ref=seat_ref)
        captcha_token = data.get("token", "")
        if not captcha_token:
            logging.info("获取文字点选验证码失败（可能不需要文字验证）")
            return ""

        # 检查是否返回了有效的验证码数据
        if "imageVerificationVo" not in data:
            logging.warning(f"文字点选返回数据异常: {json.dumps(data, ensure_ascii=False)[:200]}")
            return ""

        vo = data["imageVerificationVo"]
        logging.info(f"  originImage: {vo.get('originImage', 'N/A')[:60]}")
        logging.info(f"  context: {vo.get('context', 'N/A')}")

        # 尝试图鉴
        result = self._solve_via_ttshitu(data)
        if result:
            return result

        # 尝试超级鹰
        result = self._solve_via_chaojiying(data)
        if result:
            return result

        # Fallback: 本地 OCR
        return self._solve_text_click_local(data)

    # ===================== 超级鹰集成 =====================
    def _solve_via_chaojiying(self, data: dict) -> str:
        """通过超级鹰平台识别文字点选，返回 validate token"""
        if not CHAOJIYING_USER or not CHAOJIYING_PASS:
            return ""

        try:
            text_info, img_url = self._extract_text_info(data)
            if not text_info or not img_url:
                return ""

            # 下载图片
            img_data = self.session.get(img_url).content

            # 调用超级鹰 API
            coords = self._chaojiying_text_click(img_data, text_info)
            if not coords:
                return ""

            # 超级鹰返回坐标直接使用
            coord_arr = [{"x": c[0], "y": c[1]} for c in coords]
            return self._verify_captcha("textclick", data["token"],
                                        text_click_arr=coord_arr,
                                        iv=data.get("_iv", ""))

        except Exception as e:
            logging.warning(f"超级鹰识别异常: {e}")
            return ""

    @staticmethod
    def _chaojiying_text_click(img_bytes: bytes, text_info: str) -> list:
        """调用超级鹰 9005 文字点选"""
        # 超级鹰文字点选模式 code=9005
        # 需要把文字传过去，返回坐标数组
        import base64
        import urllib.request

        url = "https://upload.chaojiying.net/Upload/Processing.php"
        params = {
            "user": CHAOJIYING_USER,
            "pass2": md5(CHAOJIYING_PASS.encode()).hexdigest(),
            "softid": CHAOJIYING_SOFT_ID,
            "codetype": "9005",
            "textcontent": text_info,
            "file_base64": base64.b64encode(img_bytes).decode(),
        }
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=15)
        result = resp.read().decode()
        logging.info(f"超级鹰返回: {result}")

        # 解析返回: "x1,y1|x2,y2|..."
        parts = result.split("|")
        if len(parts) < 1:
            return []
        pic_str = parts[0]
        coords = []
        for coord_str in pic_str.split(","):
            try:
                x, y = coord_str.split(",")
                coords.append([int(x), int(y)])
            except (ValueError, TypeError):
                pass
        return coords

    # ===================== 图鉴平台 ttshitu.com =====================
    def _solve_via_ttshitu(self, data: dict) -> str:
        """通过图鉴平台识别文字点选，返回 validate token"""
        if not TTSHITU_USER or not TTSHITU_PASS:
            return ""

        try:
            text_info, img_url = self._extract_text_info(data)
            if not text_info or not img_url:
                return ""

            # 下载图片（使用动态UA）
            img_host = img_url.split("/")[2]
            ver, ua = random_ua()
            c_headers = {
                "Referer": "https://captcha.chaoxing.com/",
                "Host": img_host,
                "Accept": "image/*",
                "User-Agent": ua,
            }
            img_data = self.session.get(img_url, headers=c_headers).content
            if len(img_data) < 500:
                logging.warning(f"图鉴: 图片下载失败, size={len(img_data)}")
                return ""

            coords = self._ttshitu_text_click(img_data, text_info)
            if not coords:
                return ""

            # textClickArr = 坐标数组, coordinate = 空 (抓包确认)
            # 图鉴返回的坐标已经足够精准，直接使用
            coord_arr = [{"x": c[0], "y": c[1]} for c in coords]
            return self._verify_captcha("textclick", data["token"],
                                        text_click_arr=coord_arr,
                                        iv=data.get("_iv", ""))

        except Exception as e:
            logging.warning(f"图鉴识别异常: {e}")
            return ""

    @staticmethod
    def _ttshitu_text_click(img_bytes: bytes, target_text: str) -> list:
        """调用图鉴 API - 坐标点选"""
        import base64

        url = "http://api.ttshitu.com/predict"
        payload = {
            "username": TTSHITU_USER,
            "password": TTSHITU_PASS,
            "typeid": TTSHITU_TYPEID,
            "image": base64.b64encode(img_bytes).decode(),
            "remark": target_text,  # 按顺序传递需点击的文字
        }

        resp = requests.post(url, json=payload,
                             headers={"Content-Type": "application/json"},
                             timeout=60)
        result = resp.json()
        logging.info(f"图鉴返回: {json.dumps(result, ensure_ascii=False)[:300]}")

        if not result.get("success"):
            logging.warning(f"图鉴识别失败: {result.get('message', 'unknown')}")
            return []

        # 返回格式: "x1,y1|x2,y2|..." 或 {"result": "x1,y1|x2,y2|x3,y3"}
        coord_str = result.get("data", {}).get("result", "")
        if not coord_str:
            return []

        coords = []
        for part in coord_str.split("|"):
            try:
                x_str, y_str = part.strip().split(",")
                coords.append([int(x_str), int(y_str)])
            except (ValueError, TypeError):
                logging.warning(f"图鉴坐标解析失败: {part}")
        return coords

    # ===================== 本地 OCR 文字点选 =====================
    def _solve_text_click_local(self, data: dict) -> str:
        """本地 PaddleOCR 识别文字位置"""
        try:
            from paddleocr import PaddleOCR
        except ImportError:
            logging.warning("PaddleOCR未安装，无法本地识别文字点选。"
                            "请安装: pip install paddlepaddle paddleocr")
            return ""

        text_info, img_url = self._extract_text_info(data)
        if not text_info or not img_url:
            logging.error("无法提取文字点选信息")
            return ""

        logging.info(f"需点击文字: {text_info}")

        # 下载图片
        img_bytes = self.session.get(img_url).content
        img_array = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        # OCR 识别
        try:
            ocr = PaddleOCR(lang="ch")
            results = ocr.ocr(img, cls=False)
        except Exception as e:
            logging.warning(f"PaddleOCR初始化失败: {e}")
            return ""

        if not results or not results[0]:
            logging.error("OCR未识别到文字")
            return ""

        # 筛选出匹配的文字坐标
        text_click_arr = []
        need_chars = list(text_info.replace(" ", ""))

        for line in results[0]:
            text = line[1][0]  # 识别文字
            box = line[0]      # 四点坐标
            center_x = int(sum(p[0] for p in box) / 4)
            center_y = int(sum(p[1] for p in box) / 4)

            # 检查是否匹配需要点击的文字
            for char in need_chars:
                if char in text:
                    text_click_arr.append({"x": center_x, "y": center_y})
                    need_chars.remove(char)
                    break

            if not need_chars:
                break

        if not text_click_arr:
            logging.warning(f"未匹配到文字坐标, need={text_info}, ocr结果数={len(results[0])}")
            return ""

        logging.info(f"本地OCR识别坐标: {text_click_arr}")
        return self._verify_captcha("textclick", data["token"],
                                    text_click_arr=text_click_arr,
                                    iv=data.get("_iv", ""))

    @staticmethod
    def _extract_text_info(data: dict) -> tuple:
        """从验证码返回中提取文字指令和图片URL"""
        vo = data.get("imageVerificationVo", {})

        # context 格式: '"作" "收" "员"' -> 提取出 "作收员"
        text_info_raw = vo.get("context") or vo.get("textList") or vo.get("targetList") or ""
        if text_info_raw:
            import re
            chars = re.findall(r'"([^"]*)"', text_info_raw)
            text_info = "".join(chars)
        else:
            text_info = ""

        # 图片URL
        img_url = vo.get("originImage") or vo.get("bgImage") or vo.get("shadeImage") or ""

        return text_info, img_url

    # ===================== 统一入口 =====================
    def solve(self, captcha_type: str = "slide", seat_ref: str = "") -> str:
        """
        统一验证码解决入口
        captcha_type: "slide"/"textclick"/"none"（由服务器 captcha/type API 决定）
        返回 validate token，失败返回 ""
        """
        logging.info(f"开始解决验证码, type={captcha_type}")

        if captcha_type == "none":
            return "1"
        elif captcha_type in ("text", "textclick"):
            return self.solve_text_click(seat_ref=seat_ref)
        else:
            # slide 或 fallback
            return self.solve_slide(seat_ref=seat_ref)



if __name__ == "__main__":
    # 单独测试验证码模块
    import urllib.parse
    logging.basicConfig(level=logging.INFO)

    ver, ua = random_ua()
    session = requests.Session(impersonate=f"chrome{ver}")
    headers = {
        "Referer": "https://office.chaoxing.com/",
        "Host": "captcha.chaoxing.com",
        "Sec-Ch-Ua": f'"Google Chrome";v="{ver}", "Chromium";v="{ver}", "Not.A/Brand";v="24"',
        "User-Agent": ua,
    }

    solver = CaptchaSolver(session, headers)
    # 测试滑块
    validate = solver.solve_slide()
    print(f"滑块结果: {validate}")
