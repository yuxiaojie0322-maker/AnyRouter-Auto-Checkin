#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import base64
import json
import time
import traceback
from datetime import datetime, timezone, timedelta
import requests

# 环境变量配置 (在 GitHub Actions Secrets 中配置)
USER_ID      = os.getenv("USER_ID", "").strip()       # 用户ID (如: 6 位数)
SESSION      = os.getenv("SESSION", "").strip()       # 登录 Session Cookie
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()  # Telegram Bot Token (可选)
TG_CHAT_ID   = os.getenv("TG_CHAT_ID", "").strip()    # Telegram Chat ID (可选)

SITE_URL = "https://anyrouter.top"
SESSION_TTL_DAYS = 30         # Session 默认有效期约 30 天
SESSION_THRESHOLD_DAYS = 3    # 剩余小于 3 天触发报警
QUOTA_PER_DOLLAR = 500000     # 500,000 Quota = 1 USD
WAF_COOKIE_NAMES = ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]


def log(level: str, msg: str):
    """带时间戳的标准日志输出"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def decode_session_timestamp(session_value: str) -> int | None:
    """尝试从 Gorilla / SecureCookie 格式中解析创建时间戳"""
    if not session_value:
        return None

    # 策略 1: 直接按 | 分割 (标准 gorilla securecookie: timestamp|data|mac)
    parts = session_value.split("|")
    if parts and parts[0].strip().isdigit():
        return int(parts[0].strip())

    # 策略 2: URL 编码的管道符 (%7C)
    if "%7C" in session_value or "%7c" in session_value:
        decoded_url = session_value.replace("%7C", "|").replace("%7c", "|")
        parts = decoded_url.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())

    # 策略 3: Base64 编码的 Cookie
    try:
        padded = session_value + "=" * ((4 - len(session_value) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
        except Exception:
            decoded = base64.b64decode(padded)
        decoded_str = decoded.decode("utf-8", errors="ignore")
        parts = decoded_str.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())
    except Exception:
        pass

    return None


def check_session_expiry(session_value: str):
    """检查 Session 剩余有效期"""
    timestamp = decode_session_timestamp(session_value)
    if not timestamp:
        log("WARN", "无法从 Session 中解析时间戳，跳过有效期自动推算")
        return None, False

    try:
        created_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        expiry_time = created_time + timedelta(days=SESSION_TTL_DAYS)
        now = datetime.now(tz=timezone.utc)

        remaining = expiry_time - now
        remaining_days = remaining.total_seconds() / 86400

        created_local = created_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        expiry_local = expiry_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")

        log("INFO", f"Session 创建时间: {created_local}")
        log("INFO", f"预计过期时间: {expiry_local}")
        log("INFO", f"剩余有效时间: {remaining_days:.1f} 天")

        need_alert = remaining_days < SESSION_THRESHOLD_DAYS
        if need_alert:
            log("WARN", f"⚠️ Session 仅剩 {remaining_days:.1f} 天有效，请注意及时在网页端重新登录并更新 Secret！")

        return remaining_days, need_alert
    except Exception as e:
        log("WARN", f"计算 Session 有效期异常: {e}")
        return None, False


def send_telegram(message: str) -> bool:
    """推送通知到 Telegram"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("INFO", "未配置 Telegram Bot Token 或 Chat ID，跳过推送")
        return False

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=20)
        if resp.status_code == 200:
            log("INFO", "Telegram 消息发送成功")
            return True
        else:
            log("WARN", f"Telegram 发送失败: HTTP {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        log("ERROR", f"Telegram 请求异常: {e}")
        return False


def get_waf_cookies() -> dict:
    """
    优先通过轻量级 HTTP 请求获取 WAF Cookie (acw_tc, cdn_sec_tc)；
    若未获取全或遇到拦截，再回退到 Playwright 浏览器模拟。
    """
    waf_cookies = {}
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # 1. 尝试直接通过 requests 抓取登录页响应头中的 Set-Cookie
    try:
        log("INFO", "尝试直接请求登录页获取 WAF Cookie...")
        resp = requests.get(f"{SITE_URL}/login", headers=headers, timeout=15)
        for name in WAF_COOKIE_NAMES:
            if name in resp.cookies:
                waf_cookies[name] = resp.cookies.get(name)

        if "acw_tc" in waf_cookies or "cdn_sec_tc" in waf_cookies:
            log("INFO", f"通过直接请求成功获取 WAF Cookie: {list(waf_cookies.keys())}")
            # 如果无需 JS 挑战计算 acw_sc__v2，直接返回
            return waf_cookies
    except Exception as e:
        log("WARN", f"直接获取 WAF Cookie 失败，切换到 Playwright: {e}")

    # 2. 回退使用 Playwright
    log("INFO", "启动 Playwright 浏览器获取完整 WAF Cookie...")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=headers["User-Agent"],
            )
            page = context.new_page()

            try:
                page.goto(f"{SITE_URL}/login", wait_until="domcontentloaded", timeout=25000)
                page.wait_for_timeout(3000)
            except Exception as e:
                log("WARN", f"Playwright 加载页面超时或报错: {e}")

            for cookie in context.cookies():
                name = cookie.get("name")
                value = cookie.get("value")
                if name in WAF_COOKIE_NAMES and value:
                    waf_cookies[name] = value

            browser.close()
    except Exception as e:
        log("ERROR", f"Playwright 执行异常: {e}")

    log("INFO", f"最终获取到 WAF Cookie: {list(waf_cookies.keys())}")
    return waf_cookies


def build_headers() -> dict:
    """构建与网页端一致的 API 请求头"""
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": SITE_URL,
        "Origin": SITE_URL,
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "new-api-user": USER_ID,
    }


def get_user_info(session: requests.Session, headers: dict) -> dict | None:
    """获取用户个人信息与余额配额"""
    url = f"{SITE_URL}/api/user/self"
    try:
        resp = session.get(url, headers=headers, timeout=25)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                user_data = data.get("data", {})
                return {
                    "quota": user_data.get("quota", 0),
                    "used_quota": user_data.get("used_quota", 0),
                    "username": user_data.get("username", ""),
                    "id": user_data.get("id", USER_ID),
                    "raw": user_data,
                }
            else:
                log("WARN", f"API 返回错误响应: {data}")
        else:
            log("WARN", f"获取用户信息失败: HTTP {resp.status_code} - {resp.text[:200]}")
    except Exception as e:
        log("WARN", f"请求用户信息接口异常: {e}")

    return None


def do_check_in(session: requests.Session, headers: dict) -> tuple[bool, str]:
    """
    调用签到接口 POST /api/user/sign_in
    返回: (是否成功或已签, 状态提示文本)
    """
    url = f"{SITE_URL}/api/user/sign_in"

    checkin_headers = headers.copy()
    checkin_headers["Content-Type"] = "application/json"
    checkin_headers["X-Requested-With"] = "XMLHttpRequest"

    try:
        resp = session.post(url, headers=checkin_headers, timeout=25)
        log("INFO", f"签到接口响应: HTTP {resp.status_code}")

        if resp.status_code == 200:
            try:
                result = resp.json()
                msg = str(result.get("msg") or result.get("message") or "")
                
                # 检查成功标记
                if result.get("ret") == 1 or result.get("code") == 0 or result.get("success"):
                    log("INFO", "✅ 签到成功！")
                    return True, "✅ 签到成功"

                # 检查今日已签到
                already_keywords = ["已经签到", "已签到", "重复签到", "already checked", "already signed"]
                if any(kw in msg.lower() for kw in already_keywords):
                    log("INFO", f"今日此前已签到: {msg}")
                    return True, "ℹ️ 今日已签到"

                log("WARN", f"签到接口返回失败: {result}")
                return False, f"⚠️ 签到失败: {msg or '未知响应'}"

            except json.JSONDecodeError:
                if "success" in resp.text.lower():
                    log("INFO", "✅ 签到成功 (非 JSON 响应包含 success)")
                    return True, "✅ 签到成功"
                return False, f"⚠️ 签到响应格式异常: {resp.text[:100]}"
        else:
            return False, f"⚠️ 签到 HTTP 异常: {resp.status_code}"
    except Exception as e:
        log("ERROR", f"签到网络请求异常: {e}")
        return False, f"❌ 网络请求异常: {e}"


def format_balance(quota: int) -> str:
    """将 quota 配额转换为美元显示"""
    if quota is None:
        return "N/A"
    balance = quota / QUOTA_PER_DOLLAR
    if balance == int(balance):
        return f"${int(balance)}"
    return f"${balance:.2f}"


def run_checkin():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log("INFO", "=" * 50)
    log("INFO", "Anyrouter 自动签到任务启动")
    log("INFO", f"执行时间: {now_str}")
    log("INFO", f"用户 ID: {USER_ID or '未配置'}")
    log("INFO", "=" * 50)

    if not SESSION:
        err_msg = "❌ 错误: SESSION 未配置，请在 GitHub Secrets 中配置 SESSION"
        log("ERROR", err_msg)
        send_telegram(f"❌ <b>Anyrouter 签到失败</b>\n\n原因: SESSION 未配置")
        sys.exit(1)

    # 1. 获取 WAF Cookie
    waf_cookies = get_waf_cookies()

    # 2. 构造 requests Session
    session = requests.Session()
    all_cookies = dict(waf_cookies)
    all_cookies["session"] = SESSION
    if USER_ID:
        all_cookies["user_id"] = str(USER_ID)

    for name, value in all_cookies.items():
        session.cookies.set(name, value, domain="anyrouter.top", path="/")

    headers = build_headers()

    # 3. 登录有效性验证 & 签到前余额
    log("INFO", "验证 Session 有效性并获取签到前余额...")
    user_info_before = get_user_info(session, headers)

    if not user_info_before:
        log("ERROR", "用户鉴权失败，Session 已失效！")
        send_telegram(
            f"❌ <b>Anyrouter 登录失败</b>\n\n"
            f"👤 账户 ID: <code>{USER_ID}</code>\n"
            f"⏱️ 时间: {now_str}\n"
            f"⚠️ 原因: Session 已过期或无效，请在浏览器重新登录并更新 GitHub Secret <b>SESSION</b>"
        )
        sys.exit(1)

    username = user_info_before.get("username", "")
    balance_before_val = user_info_before.get("quota", 0)
    balance_before_str = format_balance(balance_before_val)

    log("INFO", f"✅ 登录成功！用户名: {username} | 签到前余额: {balance_before_str}")

    # 4. 执行签到
    log("INFO", "调用签到接口...")
    checkin_success, checkin_status_text = do_check_in(session, headers)

    # 5. 等待 3 秒后刷新最新余额
    log("INFO", "等待 3 秒后获取刷新后余额...")
    time.sleep(3)
    user_info_after = get_user_info(session, headers)

    balance_after_val = user_info_after.get("quota", balance_before_val) if user_info_after else balance_before_val
    balance_after_str = format_balance(balance_after_val)
    log("INFO", f"刷新后余额: {balance_after_str}")

    quota_diff = balance_after_val - balance_before_val
    if quota_diff > 0:
        gain_str = f" (+{format_balance(quota_diff)})"
    else:
        gain_str = ""

    # 6. 检测 Session 有效期并提示
    remaining_days, need_alert = check_session_expiry(SESSION)
    if need_alert:
        session_tips = f"⚠️ <b>Session 仅剩 {remaining_days:.1f} 天有效</b>，请尽快在网页重新登录并更新 Secret！"
    elif remaining_days is not None:
        session_tips = f"✅ Session 正常 (剩余约 {remaining_days:.1f} 天)"
    else:
        session_tips = "ℹ️ Session 有效期未解析 (运行正常)"

    # 7. 组装并发送 Telegram 通知
    title_icon = "🎁" if checkin_success else "⚠️"
    msg_lines = [
        f"{title_icon} <b>Anyrouter 签到提醒</b>",
        "",
        f"👤 <b>用户</b>: {username} (ID: <code>{USER_ID}</code>)",
        f"📊 <b>签到状态</b>: {checkin_status_text}",
        f"💰 <b>签到前余额</b>: {balance_before_str}",
        f"💰 <b>签到后余额</b>: {balance_after_str}{gain_str}",
        f"⏱️ <b>执行时间</b>: {now_str}",
        f"🔑 <b>凭据状态</b>: {session_tips}",
    ]
    send_telegram("\n".join(msg_lines))

    log("INFO", "=== 签到任务执行完毕 ===")


def main():
    try:
        run_checkin()
    except KeyboardInterrupt:
        log("WARN", "手动中断退出")
        sys.exit(130)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        log("ERROR", f"未捕获全局异常: {err}")
        log("ERROR", traceback.format_exc())
        send_telegram(
            f"❌ <b>Anyrouter 运行异常</b>\n\n"
            f"👤 用户: <code>{USER_ID}</code>\n"
            f"📝 错误: <code>{err}</code>\n"
            f"⏱️ 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
