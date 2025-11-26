# config.py
import json
import logging
import os
import platform
from pathlib import Path
from typing import Any, Dict


# --- 常量定义 ---
def get_config_dir() -> Path:
    """根据操作系统获取配置目录"""
    if platform.system() == "Windows":
        # Windows
        appdata = os.getenv("APPDATA")
        if appdata:
            return Path(appdata) / "ww_manager"
        return Path.home() / "AppData" / "Roaming" / "ww_manager"
    else:
        # Linux / macOS
        return Path.home() / ".config" / "ww_manager"


CONFIG_DIR = get_config_dir()
CONFIG_FILE = CONFIG_DIR / "config.json"

SERVER_CONFIGS = {
    "cn": {
        "api_url": "https://prod-cn-alicdn-gamestarter.kurogame.com/launcher/game/G152/10003_Y8xXrXk65DqFHEDgApn3cpK5lfczpFx5/index.json",
        "appId": "10003",
    },
    "global": {
        "api_url": "https://prod-alicdn-gamestarter.kurogame.com/launcher/game/G153/50004_obOHXFrFanqsaIEOmuKroCcbZkQRBC7c/index.json",
        "appId": "50004",
    },
    "bilibili": {
        "api_url": "https://prod-cn-alicdn-gamestarter.kurogame.com/launcher/game/G152/10004_j5GWFuUFlb8N31Wi2uS3ZAVHcb7ZGN7y/index.json",
        "appId": "10004",
    },
}

APPID_TO_SERVER = {v["appId"]: k for k, v in SERVER_CONFIGS.items()}

SERVER_DIFF_FILES = {
    "cn": [
        "Client/Binaries/Win64/kuro_login.dll",
        "Client/Content/Paks/pakchunk1-Kuro-Win64-Shipping.pak",
    ],
    "bilibili": [
        "Client/Binaries/Win64/bilibili_sdk.dll",
        "Client/Content/Paks/pakchunk1-Bilibili-Win64-Shipping.pak",
    ],
    "global": [
        "Client/Binaries/Win64/kuro_login.dll",
        "Client/Content/Paks/pakchunk1-Kuro-Win64-Shipping.pak",
    ],
}


# --- 配置管理 ---
def load_app_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.getLogger("WW_Manager").warning(f"无法加载配置文件 {CONFIG_FILE}: {e}")
        return {}


def save_app_config(config: Dict[str, Any]) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logging.getLogger("WW_Manager").error(f"无法保存配置 {CONFIG_FILE}: {e}")
