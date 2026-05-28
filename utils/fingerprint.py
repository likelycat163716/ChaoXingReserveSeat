"""
动态指纹模块：随机化浏览器指纹参数，避免被固定特征识别
"""
import random
import time
from typing import Tuple

# ===================== Chrome UA =====================
# 统一使用 Chrome 120，模拟普通用户长期不升级浏览器的场景
_UNIFIED_VERSION = "120"
_UNIFIED_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def random_ua() -> Tuple[str, str]:
    """返回 (chrome_version_str, full_ua_string)，统一使用 Chrome 120"""
    return (_UNIFIED_VERSION, _UNIFIED_UA)


def build_sec_ch_ua(version: str) -> str:
    """根据 Chrome 版本号生成 Sec-Ch-Ua 头"""
    return f'"Google Chrome";v="{version}", "Chromium";v="{version}", "Not.A/Brand";v="24"'


def random_callback() -> str:
    """
    生成随机的 JSONP callback 函数名
    真实浏览器中可能用 cx_captcha_function、jQuery、jsonp 等不同前缀
    """
    ts = int(time.time() * 1000)
    patterns = [
        lambda: f"cx_captcha_function_{random.randint(1000, 9999)}_{ts}",
        lambda: f"jQuery{random.randint(100000000, 999999999)}_{ts}",
        lambda: f"jsonp_{ts}_{random.randint(100, 999)}",
        lambda: f"_callback_{random.randint(10000, 99999)}_{ts}",
    ]
    return random.choice(patterns)()


def random_delay(min_s: float = 0.3, max_s: float = 2.0) -> float:
    """生成随机等待时间，模拟真人操作间隔"""
    return random.uniform(min_s, max_s)
