# incremental.py
"""
增量更新模块：处理 krpdiff 增量包的下载和应用

使用方式与 predownload 类似：
1. ww incremental     - 提前下载增量包（仅在新版本预下载开放期间可用）
2. ww incremental --apply  - 应用已下载的增量包

支持 cn、global、bilibili 三个服务器
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path, PurePosixPath
from queue import Empty, Queue
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

import requests
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.text import Text

from ww_manager.download import RAINBOW_COLORS, NetworkError

logger = logging.getLogger("WW_Manager")


HPATCHZ_REPO = "timetetng/wutheringwaves-cli-manager"
HPATCHZ_VERSION = "hpatchz-v4.8.0"
HPATCHZ_FILENAME = "hpatchz.exe"


class ApplySpinnerColumn(SpinnerColumn):
    """只为正在运行的增量包子任务显示 spinner。"""

    def render(self, task):
        if task.fields.get("kind") == "group":
            return super().render(task)
        return Text("")


class ApplyRainbowBarColumn(BarColumn):
    """总任务使用彩虹进度条，子任务不显示 bar。"""

    def render(self, task):
        if task.fields.get("kind") == "overall":
            color = RAINBOW_COLORS[task.id % len(RAINBOW_COLORS)]
            self.complete_style = color
            self.finished_style = color
            return super().render(task)
        return Text("")


class ApplyPercentageColumn(ProgressColumn):
    """只为总任务显示百分比。"""

    def render(self, task):
        if task.total is None:
            return Text("")
        percentage = task.percentage or 0
        return Text(f"{percentage:>3.1f}%", style="progress.percentage")


class ApplyCountColumn(ProgressColumn):
    """只为总任务显示 (完成数/总数)。"""

    def render(self, task):
        if task.total is None:
            return Text("")
        return Text(f"({int(task.completed)}/{int(task.total)})")


class IncrementalError(Exception):
    """增量更新相关错误"""

    pass


def check_wine_available() -> bool:
    """检查 wine 是否可用"""
    if platform.system() == "Windows":
        return True
    return shutil.which("wine") is not None


def check_hpatchz_requirements() -> Tuple[bool, str]:
    """检查增量更新所需的环境是否满足"""
    if platform.system() != "Windows":
        wine_path = shutil.which("wine")
        if not wine_path:
            return False, (
                "增量更新需要 wine 环境。\n"
                "请安装 wine: sudo apt install wine (Ubuntu/Debian) 或 sudo pacman -S wine (Arch)\n"
                "或者使用 'ww sync' 进行全量同步。"
            )
        logger.info(f"使用 wine: {wine_path}")
    return True, ""


def get_hpatchz_path(cache_dir: Path) -> Path:
    """获取或下载 hpatchz.exe"""
    hpatchz_path = cache_dir / "hpatchz.exe"

    if hpatchz_path.exists():
        logger.debug(f"使用缓存的 hpatchz.exe: {hpatchz_path}")
        return hpatchz_path

    logger.info("正在下载 hpatchz.exe...")

    download_url = f"https://github.com/{HPATCHZ_REPO}/releases/download/{HPATCHZ_VERSION}/{HPATCHZ_FILENAME}"

    try:
        response = requests.get(download_url, timeout=30, stream=True)
        response.raise_for_status()

        hpatchz_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hpatchz_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        os.chmod(hpatchz_path, 0o755)
        logger.info(f"hpatchz.exe 已下载到: {hpatchz_path}")
        return hpatchz_path

    except Exception as e:
        if hpatchz_path.exists():
            hpatchz_path.unlink()
        raise IncrementalError(f"下载 hpatchz.exe 失败: {e}")


def _http_get_json(url: str) -> Optional[Any]:
    """下载并解析 JSON"""
    try:
        headers = {"User-Agent": "WW-Manager/2.0"}
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"HTTP 请求失败 {url}: {e}")
        return None


def _get_krpdiff_size(url: str) -> Optional[int]:
    """通过 HEAD 请求获取 krpdiff 文件大小"""
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "WW-Manager/2.0"})
        with urlopen(req, timeout=10) as rsp:
            cl = rsp.headers.get("Content-Length")
            if cl:
                return int(cl)
    except Exception as e:
        logger.debug(f"HEAD 请求获取文件大小失败 {url}: {e}")
    return None


def _calculate_file_md5(file_path: Path) -> str:
    """计算文件 MD5"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096 * 1024), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _is_diff_resource(dest: str) -> bool:
    """判断资源路径是否是增量文件"""
    return dest.lower().endswith((".krdiff", ".krpdiff"))


def _resource_rel_path(dest: str) -> Path:
    """将资源 dest 转为相对路径，避免意外的绝对路径拼接"""
    normalized = dest.replace("\\", "/").lstrip("/")
    rel_path = PurePosixPath(normalized)
    if not normalized or ".." in rel_path.parts or (rel_path.parts and rel_path.parts[0].endswith(":")):
        raise IncrementalError(f"非法资源路径: {dest}")
    return Path(*rel_path.parts)


def _backup_path(path: Path) -> Path:
    """获取替换文件时使用的备份路径"""
    return path.with_suffix(path.suffix + ".bak")


def _format_progress_log(level: str, msg: str) -> str:
    """生成 Rich Progress 中手动输出日志的统一格式。"""
    return f"{time.strftime('%H:%M:%S')} [{level}] {msg}"


def _emit_progress_log(progress: Optional[Progress], level: str, msg: str) -> None:
    """在 Rich Progress 上方输出带时间和级别的日志；无 Progress 时回退到 logging。"""
    style_map = {"INFO": "dim", "WARNING": "yellow", "ERROR": "red"}
    if progress:
        progress.console.print(_format_progress_log(level, msg), style=style_map.get(level))
        return

    if level == "ERROR":
        logger.error(msg)
    elif level == "WARNING":
        logger.warning(msg)
    else:
        logger.info(msg)


def _safe_replace_file(src: Path, dest: Path, error_callback: Optional[Callable[[str], None]] = None) -> bool:
    """用已校验文件替换目标文件，失败时尽量恢复原文件"""
    backup = _backup_path(dest)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if backup.exists():
            backup.unlink()
        if dest.exists():
            shutil.move(dest, backup)
        shutil.move(src, dest)
        if backup.exists():
            backup.unlink()
        return True
    except Exception as e:
        message = f"替换文件失败: {dest} ({e})"
        if error_callback:
            error_callback(message)
        else:
            logger.error(message)
        try:
            if dest.exists() and backup.exists():
                dest.unlink()
            if backup.exists() and not dest.exists():
                shutil.move(backup, dest)
        except Exception as restore_error:
            message = f"恢复备份失败: {dest} ({restore_error})"
            if error_callback:
                error_callback(message)
            else:
                logger.error(message)
        return False


class IncrementalManager:
    """统一的增量更新管理器，支持 cn、global、bilibili"""

    def __init__(self, game_folder: Path, server_type: str, api_data: Dict, cdn_base: str):
        self.game_folder = game_folder
        self.server_type = server_type
        self.cdn_base = cdn_base.rstrip("/")
        self.api_data = api_data
        self.cache_dir = game_folder / ".ww_manager_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.hpatchz_path: Optional[Path] = None
        self._index_file: Optional[Dict] = None
        self._verified_staged_patch_dests: set[str] = set()
        self._verified_staged_patch_lock = threading.Lock()

    @property
    def default_config(self) -> Dict:
        """获取默认配置（始终可用）"""
        return self.api_data.get("default", {}).get("config", {})

    @property
    def predownload_config(self) -> Dict:
        """获取预下载配置（仅在预下载开放期间存在）"""
        return self.api_data.get("predownload", {}).get("config", {})

    @property
    def index_file(self) -> Optional[Dict]:
        """获取 indexFile.json（懒加载）"""
        if self._index_file is None:
            self._index_file = self._load_index_file()
        return self._index_file

    def _load_index_file(self) -> Optional[Dict]:
        """加载 indexFile.json"""
        patch_info = self._find_matching_patch()
        if not patch_info:
            return None

        index_url = self._build_index_url(patch_info)
        if not index_url:
            return None

        return _http_get_json(index_url)

    def _get_all_patch_configs(self) -> List[Dict]:
        """获取所有 patchConfig，合并 predownload 和 default 两个来源"""
        configs = []
        predownload_configs = self.predownload_config.get("patchConfig", [])
        if predownload_configs:
            configs.extend(predownload_configs)
            logger.debug(
                f"从 predownload.config 获取 {len(predownload_configs)} 个 patchConfig: "
                f"{[p.get('version') for p in predownload_configs[:5]]}..."
            )
        default_configs = self.default_config.get("patchConfig", [])
        if default_configs:
            # 避免重复（以 predownload 的为准）
            predownload_versions = {p.get("version") for p in predownload_configs}
            new_from_default = [p for p in default_configs if p.get("version") not in predownload_versions]
            configs.extend(new_from_default)
            logger.debug(
                f"从 default.config 获取 {len(default_configs)} 个 patchConfig，去重后新增 {len(new_from_default)} 个"
            )
        return configs

    def _find_matching_patch(self) -> Optional[Dict]:
        """从 patchConfig 中找到匹配当前版本的增量配置（合并 predownload 和 default 来源）"""
        patch_configs = self._get_all_patch_configs()
        if not patch_configs:
            logger.debug("patchConfig 为空（predownload 和 default 均无 patchConfig）")
            return None

        current_version = self.get_current_version()
        if not current_version:
            logger.debug("无法获取当前游戏版本（launcherDownloadConfig.json 不存在或无效）")
            return None

        for patch in patch_configs:
            if patch.get("version") == current_version:
                logger.debug(
                    f"匹配到增量配置: version={current_version}, "
                    f"indexFile={patch.get('indexFile', 'N/A')[:80]}, "
                    f"baseUrl={patch.get('baseUrl', 'N/A')}, "
                    f"size={patch.get('size', 0) / 1024 / 1024:.0f}MB"
                )
                return patch

        available = [p.get("version") for p in patch_configs]
        logger.debug(
            f"当前版本 {current_version} 不在 {len(available)} 个 patchConfig 中，"
            f"可用版本范围: {available[0]} ~ {available[-1]}"
        )
        return None

    def _build_index_url(self, patch_info: Dict) -> Optional[str]:
        """构建 indexFile URL"""
        index_file_path = patch_info.get("indexFile")
        if not index_file_path:
            logger.debug("patch_info 中缺少 indexFile 字段")
            return None
        url = f"{self.cdn_base}/{index_file_path.lstrip('/')}"
        logger.debug(f"indexFile URL: {url}")
        return url

    def _build_krpdiff_url(self, krpdiff_name: str) -> str:
        """构建 krpdiff 下载 URL"""
        patch_info = self._find_matching_patch()
        if patch_info:
            base_url = patch_info.get("baseUrl", "")
            if base_url:
                url = f"{self.cdn_base}/{base_url.strip('/')}/{quote(krpdiff_name, safe='/:')}"
                logger.debug(f"krpdiff URL (patch): {url}")
                return url

        # 回退到 default config 的 baseUrl
        default_base = self.default_config.get("baseUrl", "")
        if default_base:
            url = f"{self.cdn_base}/{default_base.strip('/')}/{quote(krpdiff_name, safe='/:')}"
            logger.debug(f"krpdiff URL (default): {url}")
            return url
        logger.debug(f"krpdiff URL (fallback): {self.cdn_base}/resources/{krpdiff_name}")
        return f"{self.cdn_base}/resources/{quote(krpdiff_name, safe='/:')}"

    def get_current_version(self) -> Optional[str]:
        """获取当前版本"""
        cfg_file = self.game_folder / "launcherDownloadConfig.json"
        if cfg_file.exists():
            try:
                data = json.loads(cfg_file.read_text())
                return data.get("version")
            except Exception:
                pass
        return None

    def get_target_version(self) -> str:
        """获取目标版本（优先 predownload，回退 default）"""
        return self.predownload_config.get("version") or self.default_config.get("version", "")

    def get_group_infos(self) -> List[Dict]:
        """获取 groupInfos 列表"""
        if not self.index_file:
            return []
        return self.index_file.get("groupInfos", [])

    def get_index_url(self) -> Optional[str]:
        """获取增量更新 indexFile 的 URL"""
        patch_info = self._find_matching_patch()
        if not patch_info:
            return None
        return self._build_index_url(patch_info)

    def _get_group_size(self, group: Dict) -> int:
        """获取 group 的增量包大小"""
        if group.get("size"):
            return group["size"]
        dst_files = group.get("dstFiles", [])
        if dst_files:
            return dst_files[0].get("size", 0)
        return 0

    def _get_resource_base_for_item(self, item: Dict, fallback_base: Optional[str] = None) -> Optional[str]:
        """获取单个资源文件的下载路径前缀，优先使用资源自己的 fromFolder"""
        item_base = item.get("fromFolder")
        if item_base:
            return item_base.rstrip("/")
        if fallback_base:
            return fallback_base.rstrip("/")
        return self._find_resource_base()

    def _build_resource_url(self, item: Dict, fallback_base: Optional[str] = None) -> Optional[str]:
        """构建完整资源文件下载 URL"""
        res_base = self._get_resource_base_for_item(item, fallback_base)
        if not res_base:
            return None
        return f"{self.cdn_base}/{res_base}/{quote(item['dest'], safe='/:')}"

    def _get_staged_complete_path(self, download_dir: Path, dest: str) -> Path:
        """获取完整资源在增量下载目录中的缓存路径"""
        return download_dir / "resources" / _resource_rel_path(dest)

    def _get_staged_patch_path(self, download_dir: Path, dest: str) -> Path:
        """获取增量包输出或回退下载文件的缓存路径"""
        return download_dir / "krpdiff_temp" / _resource_rel_path(dest)

    def _get_fallback_download_path(self, dest: str) -> Path:
        """获取回退完整下载使用的临时缓存路径"""
        return self.cache_dir / "full_download_temp" / _resource_rel_path(dest)

    def _get_repair_download_path(self, dest: str) -> Path:
        """获取校验修复下载使用的临时缓存路径"""
        return self.cache_dir / "repair_download_temp" / _resource_rel_path(dest)

    def _is_file_verified(self, path: Path, expected_size: int, expected_md5: str) -> bool:
        """检查本地文件是否符合预期大小和 MD5"""
        if not path.exists() or path.stat().st_size != expected_size:
            return False
        return _calculate_file_md5(path) == expected_md5

    def _mark_staged_patch_verified(self, dest: str) -> None:
        """记录本次 apply 过程中已经完成 MD5 校验的增量输出缓存。"""
        with self._verified_staged_patch_lock:
            self._verified_staged_patch_dests.add(dest)

    def _is_staged_patch_verified_in_this_run(self, dest: str, staged_path: Path, expected_size: int) -> bool:
        """判断 staged patch 是否已在本次 apply 中校验过，可避免迁移阶段重复读大文件算 MD5。"""
        with self._verified_staged_patch_lock:
            verified = dest in self._verified_staged_patch_dests
        return verified and staged_path.exists() and staged_path.stat().st_size == expected_size

    def download_incremental(self) -> bool:
        """下载增量更新包"""
        current_version = self.get_current_version()
        if not current_version:
            logger.error("无法获取当前版本")
            return False

        index_url = self.get_index_url()
        if not index_url:
            logger.error(
                "无法获取增量更新索引URL。可能原因：\n"
                "  1. 当前版本不在 patchConfig 中（版本太旧或太新）\n"
                "  2. 网络连接异常\n"
                "  请先运行 'ww sync' 更新到最新版本后再试。"
            )
            return False

        logger.info(f"正在获取增量更新信息: {current_version}")

        index_data = _http_get_json(index_url)
        if not index_data:
            logger.error("获取增量更新索引失败")
            return False

        self._index_file = index_data

        group_infos = self.get_group_infos()
        if not group_infos:
            logger.warning("没有找到增量更新组")
            return False

        logger.info(f"找到 {len(group_infos)} 个增量更新组")

        download_dir = self.game_folder / ".incremental_download"
        download_dir.mkdir(parents=True, exist_ok=True)

        (download_dir / "indexFile.json").write_text(json.dumps(index_data, indent=2))

        version_info = {
            "from_version": current_version,
            "to_version": self.get_target_version(),
            "server": self.server_type,
        }
        with open(download_dir / "version_info.json", "w", encoding="utf-8") as f:
            json.dump(version_info, f, indent=4)

        resources = index_data.get("resource", [])
        resource_by_dest = {r["dest"]: r for r in resources if r.get("dest")}
        complete_files = [r for r in resources if not _is_diff_resource(r["dest"])]
        res_base = None
        for r in resources:
            if r.get("fromFolder"):
                res_base = r["fromFolder"].rstrip("/")
                break
        if not res_base:
            # 回退到 patch 或 default config 的 baseUrl
            patch_info = self._find_matching_patch()
            if patch_info and patch_info.get("baseUrl"):
                res_base = patch_info["baseUrl"].rstrip("/")
            elif self.default_config.get("baseUrl"):
                res_base = self.default_config["baseUrl"].rstrip("/")

        logger.info("正在检查本地增量更新资源缓存...")

        pending_groups = []
        skipped_groups = []
        total_size = 0
        pending_size = 0

        for group in group_infos:
            krpdiff_name = group.get("dest")
            if not krpdiff_name:
                continue
            krpdiff_path = download_dir / _resource_rel_path(krpdiff_name)
            krpdiff_url = self._build_krpdiff_url(krpdiff_name)
            krpdiff_info = resource_by_dest.get(krpdiff_name, {})
            expected_size = int(krpdiff_info.get("size") or 0)
            expected_md5 = krpdiff_info.get("md5")
            if not expected_size:
                expected_size = _get_krpdiff_size(krpdiff_url) or 0

            if krpdiff_path.exists() and expected_size:
                local_size = krpdiff_path.stat().st_size
                if local_size == expected_size and (
                    not expected_md5 or _calculate_file_md5(krpdiff_path) == expected_md5
                ):
                    logger.debug(f"跳过已完成的增量包: {krpdiff_name}")
                    skipped_groups.append(krpdiff_name)
                    continue
                elif local_size < expected_size:
                    logger.info(f"检测到不完整的增量包，将重新下载: {krpdiff_name}")
                    krpdiff_path.unlink()
                else:
                    logger.info(f"文件大小或 MD5 异常，重新下载: {krpdiff_name}")
                    krpdiff_path.unlink()
            elif krpdiff_path.exists() and expected_md5:
                if _calculate_file_md5(krpdiff_path) == expected_md5:
                    logger.debug(f"跳过已完成的增量包: {krpdiff_name}")
                    skipped_groups.append(krpdiff_name)
                    continue
                logger.info(f"增量包 MD5 异常，重新下载: {krpdiff_name}")
                krpdiff_path.unlink()

            pending_groups.append((group, krpdiff_path, krpdiff_url, expected_size, expected_md5))
            if expected_size:
                resume_size = 0
                temp_path = krpdiff_path.with_suffix(krpdiff_path.suffix + ".temp")
                if temp_path.exists():
                    temp_size = temp_path.stat().st_size
                    if temp_size < expected_size:
                        resume_size = temp_size
                    elif temp_size == expected_size and (
                        not expected_md5 or _calculate_file_md5(temp_path) == expected_md5
                    ):
                        resume_size = temp_size
                    else:
                        logger.info(f"临时增量包大小或 MD5 异常，将重新下载: {krpdiff_name}")
                        temp_path.unlink()
                pending_size += expected_size - resume_size

        total_size = total_size + pending_size

        complete_tasks = []
        complete_ready_count = 0
        complete_total_count = len(complete_files)
        if complete_files:
            for item in complete_files:
                expected_size = int(item["size"])
                expected_md5 = item["md5"]
                game_path = self.game_folder / _resource_rel_path(item["dest"])
                staged_path = self._get_staged_complete_path(download_dir, item["dest"])

                if self._is_file_verified(game_path, expected_size, expected_md5):
                    complete_ready_count += 1
                    continue
                if self._is_file_verified(staged_path, expected_size, expected_md5):
                    complete_ready_count += 1
                    continue
                if staged_path.exists():
                    logger.info(f"缓存完整文件校验失败，将重新下载: {item['dest']}")
                    staged_path.unlink()

                url = self._build_resource_url(item, res_base)
                if not url:
                    logger.error(f"无法构建完整文件下载 URL: {item['dest']}")
                    return False
                complete_tasks.append(
                    {
                        "url": url,
                        "path": staged_path,
                        "size": expected_size,
                        "dest": item["dest"],
                        "md5": expected_md5,
                    }
                )
            if complete_tasks:
                complete_total = sum(t["size"] for t in complete_tasks)
                total_size += complete_total
                logger.info(f"待下载完整文件: {len(complete_tasks)} 个 ({complete_total / 1024 / 1024:.2f} MB)")

        if complete_total_count:
            logger.info(
                f"本地下载资源检查完成: 增量包 已就绪 {len(skipped_groups)}/{len(group_infos)}, "
                f"待下载 {len(pending_groups)}; 完整文件 已就绪 {complete_ready_count}/{complete_total_count}, "
                f"待下载 {len(complete_tasks)}"
            )
        else:
            logger.info(
                f"本地下载资源检查完成: 增量包 已就绪 {len(skipped_groups)}/{len(group_infos)}, "
                f"待下载 {len(pending_groups)}"
            )

        if not pending_groups and not complete_tasks:
            logger.info("无需下载，所有增量更新资源已在本地就绪")
            if complete_total_count:
                logger.info(
                    f"所有下载资源已就绪: 增量包 {len(skipped_groups)}/{len(group_infos)}, "
                    f"完整文件 {complete_ready_count}/{complete_total_count}"
                )
            else:
                logger.info(f"所有增量包已下载完成 ({len(skipped_groups)}/{len(group_infos)})")
            return True

        if pending_groups:
            logger.info(f"待下载: {len(pending_groups)} 个增量包 ({pending_size / 1024 / 1024:.2f} MB)")
        already_downloaded_count = len(skipped_groups)

        progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            expand=True,
            transient=True,
        )

        max_workers = 8
        failed_patches = []
        failed_complete_files = []
        downloaded_patch_count = already_downloaded_count
        downloaded_complete_count = complete_ready_count

        def overall_description() -> str:
            parts = [f"增量包 {downloaded_patch_count}/{len(group_infos)}"]
            if complete_total_count:
                parts.append(f"完整文件 {downloaded_complete_count}/{complete_total_count}")
            return f"下载资源 ({'，'.join(parts)})"

        download_jobs = []
        max_job_count = max(len(pending_groups), len(complete_tasks))
        for i in range(max_job_count):
            if i < len(pending_groups):
                download_jobs.append(("patch", pending_groups[i]))
            if i < len(complete_tasks):
                download_jobs.append(("complete", complete_tasks[i]))

        with progress:
            overall_task = progress.add_task(
                overall_description(),
                total=total_size if total_size > 0 else None,
            )

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for kind, payload in download_jobs:
                    if kind == "patch":
                        group, krpdiff_path, krpdiff_url, size, expected_md5 = payload
                        krpdiff_name = group.get("dest")
                        future = executor.submit(
                            self._download_file,
                            krpdiff_url,
                            krpdiff_path,
                            size,
                            expected_md5,
                            progress,
                            overall_task,
                        )
                        futures[future] = ("patch", krpdiff_name)
                    else:
                        task = payload
                        future = executor.submit(
                            self._download_and_verify_complete,
                            task["url"],
                            task["path"],
                            task["size"],
                            task["md5"],
                            progress,
                            overall_task,
                        )
                        futures[future] = ("complete", task["dest"])

                for future in as_completed(futures):
                    kind, dest = futures[future]
                    try:
                        success = future.result()
                    except Exception as e:
                        _emit_progress_log(progress, "ERROR", f"下载任务异常 {dest}: {e}")
                        success = False

                    if success:
                        if kind == "patch":
                            downloaded_patch_count += 1
                        else:
                            downloaded_complete_count += 1
                    elif kind == "patch":
                        failed_patches.append(dest)
                    else:
                        failed_complete_files.append(dest)

                    progress.update(overall_task, description=overall_description())

        if failed_patches or failed_complete_files:
            if failed_patches:
                logger.error(f"增量包下载失败: {failed_patches}")
            if failed_complete_files:
                logger.error(f"完整文件下载失败: {failed_complete_files}")
            return False

        if complete_total_count:
            logger.info(
                f"下载完成: 增量包 {downloaded_patch_count}/{len(group_infos)}, "
                f"完整文件 {downloaded_complete_count}/{complete_total_count}"
            )
        else:
            logger.info(f"增量包下载完成: {downloaded_patch_count}/{len(group_infos)}")

        return True

    def _download_file(
        self,
        url: str,
        dest: Path,
        expected_size: int,
        expected_md5: Optional[str] = None,
        progress: Optional[Progress] = None,
        overall_task_id: Optional[TaskID] = None,
    ) -> bool:
        """下载单个文件，支持断点续传和大小校验，使用 Rich Progress 显示进度"""
        dest.parent.mkdir(parents=True, exist_ok=True)

        task_id = None
        if progress:
            task_id = progress.add_task(description=dest.name, total=expected_size if expected_size > 0 else None)
            color = RAINBOW_COLORS[task_id % len(RAINBOW_COLORS)]
            progress.update(task_id, description=f"[{color}]{dest.name}[/{color}]")

        temp_file = dest.with_suffix(dest.suffix + ".temp")

        retries = 3
        success = False

        for attempt in range(retries):
            try:
                resume_byte = 0
                if temp_file.exists():
                    resume_byte = temp_file.stat().st_size
                    if expected_size > 0 and resume_byte > expected_size:
                        _emit_progress_log(progress, "INFO", f"临时文件大小异常，重新下载: {dest.name}")
                        temp_file.unlink()
                        resume_byte = 0

                if expected_size > 0 and resume_byte == expected_size:
                    if expected_md5 and _calculate_file_md5(temp_file) != expected_md5:
                        _emit_progress_log(progress, "INFO", f"临时文件 MD5 异常，重新下载: {dest.name}")
                        temp_file.unlink()
                        resume_byte = 0
                    else:
                        if progress and task_id is not None:
                            progress.update(task_id, completed=expected_size)
                        success = True
                        break

                headers = {"User-Agent": "WW-Manager/2.0"}
                if resume_byte > 0:
                    headers["Range"] = f"bytes={resume_byte}-"
                    if progress and task_id is not None:
                        progress.update(task_id, completed=resume_byte)

                mode = "ab" if resume_byte > 0 else "wb"

                req = Request(url, headers=headers)
                with urlopen(req, timeout=15) as rsp:
                    if rsp.status not in (200, 206):
                        raise NetworkError(f"HTTP {rsp.status}")
                    if resume_byte > 0 and rsp.status == 200:
                        # 服务器忽略 Range 时重新写临时文件，避免追加出损坏文件
                        resume_byte = 0
                        mode = "wb"
                        if progress and task_id is not None:
                            progress.update(task_id, completed=0)

                    with open(temp_file, mode) as f:
                        while True:
                            chunk = rsp.read(1024 * 256)
                            if not chunk:
                                break
                            f.write(chunk)

                            if progress:
                                chunk_len = len(chunk)
                                if task_id is not None:
                                    progress.update(task_id, advance=chunk_len)
                                if overall_task_id is not None:
                                    progress.update(overall_task_id, advance=chunk_len)

                if expected_size <= 0 or temp_file.stat().st_size == expected_size:
                    success = True
                    break

            except Exception as e:
                if attempt == retries - 1:
                    _emit_progress_log(progress, "ERROR", f"下载失败 {dest.name}: {e}")
                    if progress and task_id is not None:
                        progress.remove_task(task_id)
                    return False
                time.sleep(1 + attempt)

        if success and expected_md5:
            actual_md5 = _calculate_file_md5(temp_file)
            if actual_md5 != expected_md5:
                _emit_progress_log(progress, "ERROR", f"文件 MD5 不匹配: {dest.name}")
                temp_file.unlink()
                success = False

        if success:
            shutil.move(temp_file, dest)

        if progress and task_id is not None:
            progress.remove_task(task_id)

        return success

    def _apply_staged_complete_files(self, download_dir: Path) -> bool:
        """将下载阶段缓存的完整资源文件迁移到游戏目录"""
        resources = (self.index_file or {}).get("resource", [])
        complete_files = [r for r in resources if not _is_diff_resource(r["dest"])]
        if not complete_files:
            return True

        moved_count = 0
        skipped_count = 0
        failed = []

        logger.info(f"开始迁移并校验完整资源文件: 共 {len(complete_files)} 个")
        progress = Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            transient=False,
        )

        with progress:
            task_id = progress.add_task("[bold cyan]迁移完整资源", total=len(complete_files))

            for item in complete_files:
                dest = item["dest"]
                progress.update(task_id, description=f"[bold cyan]迁移完整资源: {Path(dest).name[:60]}")

                expected_size = int(item["size"])
                expected_md5 = item["md5"]
                game_path = self.game_folder / _resource_rel_path(dest)
                staged_path = self._get_staged_complete_path(download_dir, dest)

                try:
                    if self._is_file_verified(staged_path, expected_size, expected_md5):
                        if _safe_replace_file(
                            staged_path,
                            game_path,
                            lambda msg: _emit_progress_log(progress, "ERROR", msg),
                        ):
                            moved_count += 1
                        else:
                            failed.append(dest)
                        continue

                    if self._is_file_verified(game_path, expected_size, expected_md5):
                        skipped_count += 1
                        continue

                    _emit_progress_log(progress, "ERROR", f"完整文件缓存缺失或校验失败: {dest}")
                    failed.append(dest)
                finally:
                    progress.advance(task_id)

        if failed:
            logger.error(f"完整文件迁移失败: {failed}")
            return False

        logger.info(f"完整文件迁移完成: 更新={moved_count}, 已是目标版本={skipped_count}")
        return True

    def _apply_delete_files(self, delete_files: List[str]) -> int:
        """按清单删除补丁。

        indexFile.json 的 deleteFiles 字段明确列出应删除的旧资源
        残留会导致 UE 挂载覆盖新文件、热更卡死
        """
        removed = 0
        failed = 0
        for dest in delete_files or []:
            try:
                rel = _resource_rel_path(dest)
            except IncrementalError:
                logger.debug(f"跳过非法 deleteFiles 路径: {dest}")
                continue
            full = self.game_folder / rel
            if not full.exists():
                logger.debug(f"deleteFiles 目标不存在，跳过: {dest}")
                continue
            if full.is_dir():
                logger.debug(f"跳过 deleteFiles 目录: {dest}")
                continue
            try:
                full.unlink()
                removed += 1
            except OSError as e:
                failed += 1
                logger.debug(f"删除废弃文件失败 {dest}: {e}")
        if removed:
            logger.warning(f"已清理 {removed} 个废弃补丁")
        if failed:
            logger.warning(f"{failed} 个废弃补丁删除失败")
        return removed

    def _apply_staged_patch_files(self, download_dir: Path) -> bool:
        """将已校验的增量输出文件统一迁移到游戏目录"""
        resources = (self.index_file or {}).get("resource", [])
        complete_dests = {r["dest"] for r in resources if r.get("dest") and not _is_diff_resource(r["dest"])}

        patch_targets = []
        for group in self.get_group_infos():
            for dst_info in group.get("dstFiles", []):
                dest = dst_info["dest"]
                if dest in complete_dests:
                    # 官方逻辑中普通资源文件优先，patch 输出不覆盖这些完整资源。
                    continue
                patch_targets.append(dst_info)

        moved_count = 0
        skipped_count = 0
        failed = []

        if not patch_targets:
            logger.info("没有需要迁移的增量输出文件")
            return True

        logger.info(f"开始覆盖并校验增量输出文件: 共 {len(patch_targets)} 个")
        progress = Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            transient=False,
        )

        with progress:
            task_id = progress.add_task("[bold cyan]覆盖并校验增量输出", total=len(patch_targets))

            for dst_info in patch_targets:
                dest = dst_info["dest"]
                progress.update(task_id, description=f"[bold cyan]覆盖/校验: {Path(dest).name[:60]}")

                expected_size = int(dst_info["size"])
                expected_md5 = dst_info["md5"]
                game_path = self.game_folder / _resource_rel_path(dest)
                staged_path = self._get_staged_patch_path(download_dir, dest)

                try:
                    if self._is_staged_patch_verified_in_this_run(dest, staged_path, expected_size):
                        if _safe_replace_file(
                            staged_path,
                            game_path,
                            lambda msg: _emit_progress_log(progress, "ERROR", msg),
                        ):
                            moved_count += 1
                        else:
                            failed.append(dest)
                        continue

                    if self._is_file_verified(staged_path, expected_size, expected_md5):
                        if _safe_replace_file(
                            staged_path,
                            game_path,
                            lambda msg: _emit_progress_log(progress, "ERROR", msg),
                        ):
                            moved_count += 1
                        else:
                            failed.append(dest)
                        continue

                    if self._is_file_verified(game_path, expected_size, expected_md5):
                        skipped_count += 1
                        continue

                    _emit_progress_log(progress, "ERROR", f"增量输出缓存缺失或校验失败: {dest}")
                    failed.append(dest)
                finally:
                    progress.advance(task_id)

        if failed:
            logger.error(f"增量输出迁移失败: {failed}")
            return False

        logger.info(f"增量输出迁移完成: 更新={moved_count}, 已是目标版本={skipped_count}")
        return True

    def apply_incremental(self) -> bool:
        """应用已下载的增量更新包"""
        logger.info("正在准备应用增量更新...")
        logger.info("正在检查增量更新运行环境...")
        is_ok, error_msg = check_hpatchz_requirements()
        if not is_ok:
            logger.warning(f"环境检查失败: {error_msg}")
            raise IncrementalError(error_msg)

        download_dir = self.game_folder / ".incremental_download"
        version_file = download_dir / "version_info.json"

        if not download_dir.exists() or not version_file.exists():
            logger.error("未找到增量更新包，请先执行 'ww incremental' 下载")
            return False

        try:
            version_info = json.loads(version_file.read_text())
        except Exception:
            logger.error("增量更新版本信息损坏")
            return False

        if version_info.get("server") != self.server_type:
            logger.error(f"服务器不匹配: 预期 {version_info.get('server')}, 实际 {self.server_type}")
            return False

        logger.info(f"开始应用增量更新: {version_info.get('from_version')} -> {version_info.get('to_version')}")
        logger.info("正在准备 hpatchz 工具...")
        self.hpatchz_path = get_hpatchz_path(self.cache_dir)

        index_file = download_dir / "indexFile.json"
        if not index_file.exists():
            logger.error("无法找到 indexFile.json")
            return False

        try:
            self._index_file = json.loads(index_file.read_text())
        except Exception:
            logger.error("无法解析 indexFile.json")
            return False

        group_infos = self.get_group_infos()
        if not group_infos:
            logger.warning("没有增量更新组")
            return False

        max_workers = min(4, len(group_infos))
        # 大文件优先：按 group 总大小降序排列，让最大的先启动
        group_infos = sorted(group_infos, key=lambda g: self._get_group_size(g), reverse=True)
        logger.info(
            f"开始合并 {len(group_infos)} 个增量包，并发 {max_workers} 个部分大文件可能耗时数分钟，请勿中断进程。"
        )

        results = {}
        status_events = Queue()

        def group_label(dest: Optional[str]) -> str:
            if not dest:
                return "unknown"
            return Path(dest).stem

        _group_colors = RAINBOW_COLORS

        def group_color(task_idx: int) -> str:
            return _group_colors[task_idx % len(_group_colors)]

        def group_description(dest: Optional[str], stage: Optional[str] = None, color: str = "cyan") -> str:
            label = group_label(dest)
            if stage:
                return f"[{color}]{label}[/{color}] [dim]{stage}[/dim]"
            return f"[{color}]{label}[/{color}]"

        def apply_wrapper(group):
            dest = group.get("dest")

            def emit(kind: str, msg: Optional[str] = None):
                status_events.put((kind, dest, msg))

            def emit_log(level: str, msg: str):
                status_events.put(("log", level, msg))

            def update_status(msg: str):
                emit("status", msg)

            def log_info(_msg):
                # 普通成功日志不在 Rich 进度条期间输出，避免刷屏。
                pass

            def log_warning(msg):
                emit_log("WARNING", msg)

            def log_error(msg):
                emit_log("ERROR", msg)

            emit("start", "开始处理")
            try:
                dest, result = self._apply_single_group(
                    group,
                    download_dir,
                    log_info,
                    log_warning,
                    log_error,
                    update_status,
                )
                return dest, result
            except Exception as e:
                log_error(f"应用增量包异常: {e}")
                return dest, "failed"
            finally:
                emit("finish")

        progress = Progress(
            ApplySpinnerColumn("dots"),
            TextColumn("{task.description}"),
            ApplyRainbowBarColumn(bar_width=40),
            ApplyPercentageColumn(),
            ApplyCountColumn(),
            TimeElapsedColumn(),
            transient=False,
            expand=True,
        )

        with progress:
            task_id = progress.add_task("[bold cyan]应用增量包", total=len(group_infos), kind="overall")
            active_tasks = {}

            _child_color_counter = 0
            _child_color_map: dict = {}

            def drain_status_events():
                nonlocal _child_color_counter
                while True:
                    try:
                        kind, event_target, msg = status_events.get_nowait()
                    except Empty:
                        break

                    if kind in ("start", "status"):
                        child_task_id = active_tasks.get(event_target)
                        if child_task_id is None:
                            c = group_color(_child_color_counter)
                            _child_color_map[event_target] = _child_color_counter
                            _child_color_counter += 1
                            description = group_description(event_target, msg, color=c)
                            active_tasks[event_target] = progress.add_task(description, total=None, kind="group")
                        else:
                            idx = _child_color_map.get(event_target, 0)
                            description = group_description(event_target, msg, color=group_color(idx))
                            progress.update(child_task_id, description=description)
                    elif kind == "log":
                        _emit_progress_log(progress, event_target, msg)
                    elif kind == "finish":
                        child_task_id = active_tasks.pop(event_target, None)
                        _child_color_map.pop(event_target, None)
                        if child_task_id is not None:
                            progress.remove_task(child_task_id)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                pending = {executor.submit(apply_wrapper, group): group for group in group_infos}
                while pending:
                    done, pending_futures = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                    pending = pending_futures
                    drain_status_events()

                    for future in done:
                        dest, result = future.result()
                        results[dest] = result
                        progress.update(task_id, advance=1)

                    drain_status_events()

            # 兜底清理仍显示的子任务，避免异常路径残留。
            for child_task_id in list(active_tasks.values()):
                progress.remove_task(child_task_id)

        success_count = sum(1 for r in results.values() if r == "success")
        skip_count = sum(1 for r in results.values() if r == "skipped")
        fail_count = sum(1 for r in results.values() if r in ("failed", "partial_failed"))
        failed_groups = [dest for dest, r in results.items() if r in ("failed", "partial_failed")]

        logger.info(
            f"增量包合并阶段完成: 成功={success_count}, 跳过={skip_count}, "
            f"失败={fail_count}。接下来将覆盖并校验游戏目录文件。"
        )

        if fail_count > 0:
            logger.warning(f"失败组: {failed_groups}")
            logger.warning(f"有 {fail_count} 个增量包应用存在失败。请运行 'ww sync' 修复。")
            return False

        if not self._apply_staged_patch_files(download_dir):
            logger.warning("增量输出迁移失败，请运行 'ww sync' 修复。")
            return False

        if not self._apply_staged_complete_files(download_dir):
            logger.warning("完整文件迁移失败，请运行 'ww sync' 修复。")
            return False

        delete_files = (self.index_file or {}).get("deleteFiles", [])
        if delete_files:
            self._apply_delete_files(delete_files)

        logger.info("正在保存索引并清理临时目录...")
        saved_index = self.cache_dir / "indexFile.json"
        if index_file.exists():
            shutil.copy2(index_file, saved_index)
            logger.info("已保存索引到缓存")

        shutil.rmtree(download_dir)
        logger.info("已清理增量下载目录")

        self._cleanup_cache_dir()
        logger.info("已清理缓存临时目录")

        self._update_local_version(version_info.get("to_version"))
        logger.info("增量更新应用完成。建议运行 'ww sync --new' 做最终校验。")

        return True

    def _apply_single_group(
        self,
        group: Dict,
        download_dir: Path,
        log_info,
        log_warning,
        log_error,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> tuple:
        """应用单个增量更新组"""
        krpdiff_name = group.get("dest")
        src_files = group.get("srcFiles", [])
        dst_files = group.get("dstFiles", [])

        def set_status(msg: str):
            if status_callback:
                status_callback(msg)

        set_status("检查资源信息")
        if not krpdiff_name or not src_files or not dst_files:
            return krpdiff_name, "failed"

        # 检查是否所有 dst 文件都已经是最新版本（跳过已完成的分组）
        set_status("检查目标文件")
        dst_by_md5 = {d["md5"]: d for d in dst_files}
        all_dst_done = True
        for dst_info in dst_files:
            dst_full = self.game_folder / _resource_rel_path(dst_info["dest"])
            if not dst_full.exists() or dst_full.stat().st_size != int(dst_info["size"]):
                all_dst_done = False
                break
        if all_dst_done:
            # 大小匹配，抽样第一个文件做 MD5 确认，避免在跳过路径上重复校验所有 dstFiles。
            set_status("校验目标文件")
            first_dst_full = self.game_folder / _resource_rel_path(dst_files[0]["dest"])
            if _calculate_file_md5(first_dst_full) == dst_files[0]["md5"]:
                log_info(f"所有文件已为目标版本，跳过 {len(dst_files)} 个文件")
                return krpdiff_name, "skipped"

        # 检查第一个源文件的状态（决定运行 hpatchz 还是回退下载）
        set_status("检查源文件")
        first_src = src_files[0]
        first_src_path = first_src["dest"]
        first_src_md5 = first_src["md5"]
        first_src_full = self.game_folder / _resource_rel_path(first_src_path)
        backup_path = _backup_path(first_src_full)

        # 只计算一次 MD5，缓存复用
        first_local_md5 = None
        if first_src_full.exists():
            first_local_md5 = _calculate_file_md5(first_src_full)
        elif backup_path.exists():
            first_local_md5 = _calculate_file_md5(backup_path)

        if first_local_md5 is None:
            # 源文件不存在，回退下载所有 dst 文件
            set_status(f"源文件缺失，回退下载 {len(dst_files)} 个文件")
            logger.debug(f"源文件不存在: {first_src_path}, 回退下载 {len(dst_files)} 个文件")
            failed_count = 0
            for index, dst_info in enumerate(dst_files, 1):
                set_status(f"回退下载 {index}/{len(dst_files)}")
                staged_path = self._get_staged_patch_path(download_dir, dst_info["dest"])
                if not self._download_full_file_to_stage(dst_info, staged_path, log_error):
                    failed_count += 1
                    log_error(f"下载失败: {dst_info['dest']}")
                else:
                    log_info(f"已缓存完整文件: {dst_info['dest']}")
            return krpdiff_name, "failed" if failed_count > 0 else "success"

        # 检查 MD5：必须是 src 版本或已经是 dst 版本
        if first_local_md5 in dst_by_md5:
            # 已经是目标版本，但其他 dst 文件可能缺失（多文件 group 场景）
            # 仍需运行 hpatchz 来生成其他输出文件
            pass
        elif first_local_md5 != first_src_md5:
            set_status("源文件校验失败")
            log_warning(
                f"源文件 MD5 不匹配: {first_src_path} "
                f"(期望 {first_src_md5[:16]}... 或 dst MD5, 实际 {first_local_md5[:16]}...)"
            )
            return krpdiff_name, "failed"

        # 从备份恢复
        if backup_path.exists() and not first_src_full.exists():
            set_status("恢复中断文件")
            shutil.move(backup_path, first_src_full)
            log_info(f"恢复中断的更新: {first_src_path}")
            first_local_md5 = _calculate_file_md5(first_src_full)

        set_status("检查增量包")
        krpdiff_path = download_dir / _resource_rel_path(krpdiff_name)
        if not krpdiff_path.exists():
            log_error(f"增量包不存在: {krpdiff_name}")
            return krpdiff_name, "failed"

        patch_temp_dir = self.cache_dir / "patch_temp"
        patch_temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tempfile.TemporaryDirectory(prefix="ww_patch_", dir=patch_temp_dir) as temp_dir:
                set_status("准备临时目录")
                output_dir = Path(temp_dir) / "output"
                output_dir.mkdir(parents=True, exist_ok=True)

                if not self._run_hpatchz(
                    krpdiff_path,
                    output_dir,
                    src_files,
                    status_callback=set_status,
                    error_callback=log_error,
                ):
                    set_status(f"hpatchz 失败，回退下载 {len(dst_files)} 个文件")
                    log_warning(f"hpatchz 应用失败，回退到完整下载: {first_src_path} 等 {len(dst_files)} 个文件")
                    failed_count = 0
                    for index, dst_info in enumerate(dst_files, 1):
                        set_status(f"回退下载 {index}/{len(dst_files)}")
                        staged_path = self._get_staged_patch_path(download_dir, dst_info["dest"])
                        if not self._download_full_file_to_stage(dst_info, staged_path, log_error):
                            failed_count += 1
                            log_error(f"下载失败: {dst_info['dest']}")
                        else:
                            log_info(f"已缓存完整文件: {dst_info['dest']}")
                    if failed_count > 0:
                        return krpdiff_name, "failed"
                    return krpdiff_name, "success"

                # hpatchz 成功，缓存所有输出文件，最后统一校验并迁移到游戏目录
                set_status("缓存输出文件")
                fail_count = 0
                for index, dst_info in enumerate(dst_files, 1):
                    set_status(f"缓存输出 {index}/{len(dst_files)}")
                    dst_rel_path = dst_info["dest"]
                    output_file = output_dir / _resource_rel_path(dst_rel_path)
                    staged_path = self._get_staged_patch_path(download_dir, dst_rel_path)

                    if not output_file.exists():
                        set_status(f"输出缺失，回退下载 {index}/{len(dst_files)}")
                        log_warning(f"输出文件未生成: {dst_rel_path}, 回退下载")
                        if not self._download_full_file_to_stage(dst_info, staged_path, log_error):
                            fail_count += 1
                            log_error(f"回退下载也失败: {dst_rel_path}")
                        continue

                    set_status(f"校验输出 {index}/{len(dst_files)}")
                    if not self._is_file_verified(output_file, int(dst_info["size"]), dst_info["md5"]):
                        set_status(f"输出校验失败，回退下载 {index}/{len(dst_files)}")
                        log_warning(f"输出文件校验失败: {dst_rel_path}, 回退下载")
                        if not self._download_full_file_to_stage(dst_info, staged_path, log_error):
                            fail_count += 1
                            log_error(f"回退下载也失败: {dst_rel_path}")
                        continue

                    staged_path.parent.mkdir(parents=True, exist_ok=True)
                    if staged_path.exists():
                        staged_path.unlink()
                    shutil.move(output_file, staged_path)
                    self._mark_staged_patch_verified(dst_rel_path)

                if fail_count > 0:
                    return krpdiff_name, "partial_failed"

                return krpdiff_name, "success"

        finally:
            pass

    def _download_full_file_to_stage(
        self,
        dst_info: Dict,
        staged_path: Path,
        error_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """下载完整文件到指定缓存路径，不直接修改游戏目录"""
        dest = dst_info["dest"]
        expected_md5 = dst_info["md5"]
        expected_size = int(dst_info["size"])

        if self._is_file_verified(staged_path, expected_size, expected_md5):
            self._mark_staged_patch_verified(dest)
            return True
        if staged_path.exists():
            staged_path.unlink()

        url = self._build_resource_url(dst_info)
        if not url:
            message = "无法获取资源路径"
            if error_callback:
                error_callback(message)
            else:
                logger.error(message)
            return False

        logger.debug(f"下载完整文件到缓存: {dest}")
        success = self._download_and_verify(
            url,
            staged_path,
            expected_size,
            expected_md5,
            error_callback=error_callback,
            suppress_success_log=True,
        )
        if success:
            self._mark_staged_patch_verified(dest)
        return success

    def _download_full_file(self, dst_info: Dict, dest_path: Path) -> bool:
        """下载完整文件作为 hpatchz 失败的回退方案，先写入缓存再替换游戏文件"""
        dest = dst_info["dest"]
        expected_md5 = dst_info["md5"]
        expected_size = int(dst_info["size"])

        if self._is_file_verified(dest_path, expected_size, expected_md5):
            logger.info(f"完整文件已是目标版本: {dest}")
            return True

        url = self._build_resource_url(dst_info)
        if not url:
            logger.error("无法获取资源路径")
            return False

        staged_path = self._get_fallback_download_path(dest)
        if staged_path.exists() and not self._is_file_verified(staged_path, expected_size, expected_md5):
            staged_path.unlink()

        logger.info(f"下载完整文件: {dest}")
        if not self._is_file_verified(staged_path, expected_size, expected_md5):
            if not self._download_and_verify(url, staged_path, expected_size, expected_md5):
                return False

        return _safe_replace_file(staged_path, dest_path)

    def _run_hpatchz(
        self,
        krpdiff_path: Path,
        output_dir: Path,
        src_files: List[Dict],
        temp_olddir: Optional[Path] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        error_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """运行 hpatchz 应用增量包

        Args:
            krpdiff_path: 增量包路径
            output_dir: 输出目录
            src_files: 源文件列表（包含 dest 和 md5）
            temp_olddir: 预创建的临时源文件目录
            status_callback: 状态回调，用于刷新当前增量包子任务
            error_callback: 错误日志回调，用于在 Rich Progress 上方统一输出
        """

        def set_status(msg: str):
            if status_callback:
                status_callback(msg)

        def emit_error(msg: str):
            if error_callback:
                error_callback(msg)
            else:
                logger.error(msg)

        if temp_olddir is None:
            set_status("准备 hpatchz 源文件")
            # 为当前 group 创建临时源文件目录
            patch_temp_dir = self.cache_dir / "patch_temp"
            patch_temp_dir.mkdir(parents=True, exist_ok=True)
            temp_olddir = patch_temp_dir / f"olddir_{Path(krpdiff_path).stem}"
            if temp_olddir.exists():
                shutil.rmtree(temp_olddir)
            temp_olddir.mkdir(parents=True)

            # 复制所有源文件到临时目录
            for index, src_file in enumerate(src_files, 1):
                set_status(f"复制源文件 {index}/{len(src_files)}")
                src_rel_path = _resource_rel_path(src_file["dest"])
                src_full_path = self.game_folder / src_rel_path
                dst_full_path = temp_olddir / src_rel_path

                if src_full_path.exists():
                    dst_full_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_full_path, dst_full_path)

        if platform.system() == "Windows":
            cmd = [
                str(self.hpatchz_path),
                "-f",
                str(temp_olddir.absolute()) + "/",
                str(krpdiff_path.absolute()),
                str(output_dir.absolute()) + "/",
            ]
        else:
            cmd = [
                "wine",
                str(self.hpatchz_path),
                "-f",
                str(temp_olddir.absolute()) + "/",
                str(krpdiff_path.absolute()),
                str(output_dir.absolute()) + "/",
            ]

        set_status("运行 hpatchz")
        logger.debug(f"Running hpatchz: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        set_status("检查 hpatchz 结果")
        if result.returncode != 0:
            emit_error(f"hpatchz 运行失败: {result.stderr}")
            return False

        return True

    def _get_cached_target_version(self, download_dir: Path) -> Optional[str]:
        """从增量下载元信息或 API 配置获取目标版本"""
        version_file = download_dir / "version_info.json"
        if version_file.exists():
            try:
                target_version = json.loads(version_file.read_text()).get("to_version")
                if target_version:
                    return target_version
            except Exception:
                pass
        return self.get_target_version() or None

    def verify_new_version(self) -> bool:
        """校验新版本文件状态，用于增量更新后的检查"""
        download_dir = self.game_folder / ".incremental_download"
        index_file = download_dir / "indexFile.json"
        cache_index_file = self.cache_dir / "indexFile.json"

        if not index_file.exists() and not cache_index_file.exists():
            logger.error("未找到增量更新的 indexFile.json，请先执行 'ww incremental' 下载")
            return False

        index_file = index_file if index_file.exists() else cache_index_file

        try:
            index_data = json.loads(index_file.read_text())
        except Exception:
            logger.error("无法解析 indexFile.json")
            return False

        resources = index_data.get("resource", [])
        group_infos = index_data.get("groupInfos", [])
        expected_files = {}

        for group in group_infos:
            for item in group.get("dstFiles", []):
                dest = item.get("dest")
                if dest and item.get("md5") and item.get("size") is not None and not _is_diff_resource(dest):
                    expected_files[dest] = item

        for item in resources:
            dest = item.get("dest")
            if dest and item.get("md5") and item.get("size") is not None and not _is_diff_resource(dest):
                # resource 中的完整资源优先，贴近 BugFix File 使用 Resource File 的处理。
                expected_files[dest] = item

        game_files = list(expected_files.values())
        if not game_files:
            logger.error("indexFile.json 中没有可校验的新版本游戏文件")
            return False

        logger.info(f"正在校验 {len(game_files)} 个新版本文件...")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn

        ok_count = 0
        inconsistent_files = []
        missing_files = []

        with Progress(
            TextColumn("[progress.description]{task.description}", justify="left"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TimeRemainingColumn(),
            expand=True,
            transient=True,
        ) as progress:
            verify_task = progress.add_task("[cyan]校验文件...", total=len(game_files))

            def check_resource(item):
                dest_path = self.game_folder / _resource_rel_path(item["dest"])
                expected_md5 = item["md5"]
                expected_size = int(item["size"])

                status = "ok"
                if not dest_path.exists():
                    status = "missing"
                elif dest_path.stat().st_size != expected_size:
                    status = "size_mismatch"
                else:
                    actual_md5 = _calculate_file_md5(dest_path)
                    if actual_md5 != expected_md5:
                        status = "md5_mismatch"
                return status, item["dest"]

            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = {executor.submit(check_resource, item): item for item in game_files}

                for future in as_completed(futures):
                    status, dest = future.result()
                    progress.advance(verify_task)

                    if status == "ok":
                        ok_count += 1
                    elif status == "missing":
                        missing_files.append(dest)
                    else:
                        inconsistent_files.append(dest)

        logger.info(f"校验完成: 正常={ok_count}, 不一致={len(inconsistent_files)}, 缺失={len(missing_files)}")

        delete_files = index_data.get("deleteFiles", [])
        if delete_files:
            self._apply_delete_files(delete_files)

        target_version = self._get_cached_target_version(download_dir)

        if not inconsistent_files and not missing_files:
            logger.info("所有游戏文件状态正常")
            self._update_local_version(target_version or index_data)
            return True

        repair_needed = inconsistent_files + missing_files
        logger.warning(f"需要修复的游戏文件: {repair_needed}")

        res_base = self._find_resource_base()
        if not res_base:
            logger.warning("无法获取全局新版本资源路径，将尝试使用单个资源的 fromFolder")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        from rich.progress import (
            BarColumn,
            DownloadColumn,
            Progress,
            TextColumn,
            TimeRemainingColumn,
            TransferSpeedColumn,
        )

        game_res_map = {r["dest"]: r for r in game_files}
        repair_count = 0
        fail_count = 0
        total_size = sum(int(game_res_map[d]["size"]) for d in repair_needed)

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            overall_task = progress.add_task("修复文件", total=total_size)

            def download_repair(dest):
                item = game_res_map.get(dest)
                if not item:
                    return False, dest, 0
                final_path = self.game_folder / _resource_rel_path(dest)
                staged_path = self._get_repair_download_path(dest)
                expected_md5 = item["md5"]
                expected_size = int(item["size"])
                file_name = Path(dest).name

                if self._is_file_verified(final_path, expected_size, expected_md5):
                    return True, dest, expected_size

                if staged_path.exists() and not self._is_file_verified(staged_path, expected_size, expected_md5):
                    staged_path.unlink()

                url = self._build_resource_url(item, res_base)
                if not url:
                    _emit_progress_log(progress, "ERROR", f"无法构建修复文件下载 URL: {dest}")
                    return False, dest, expected_size

                task_id = progress.add_task(description=f"[cyan]{file_name[:40]}[/cyan]", total=expected_size)

                try:
                    if not self._is_file_verified(staged_path, expected_size, expected_md5):
                        headers = {"User-Agent": "WW-Manager/2.0"}
                        response = requests.get(url, headers=headers, timeout=60, stream=True)
                        response.raise_for_status()

                        staged_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(staged_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=1024 * 256):
                                f.write(chunk)
                                progress.update(task_id, advance=len(chunk))
                    else:
                        progress.update(task_id, completed=expected_size)

                    progress.remove_task(task_id)

                    if not self._is_file_verified(staged_path, expected_size, expected_md5):
                        _emit_progress_log(progress, "ERROR", f"修复文件校验失败: {dest}")
                        if staged_path.exists():
                            staged_path.unlink()
                        return False, dest, expected_size

                    if not _safe_replace_file(
                        staged_path,
                        final_path,
                        lambda msg: _emit_progress_log(progress, "ERROR", msg),
                    ):
                        return False, dest, expected_size

                    return True, dest, expected_size

                except Exception as e:
                    _emit_progress_log(progress, "ERROR", f"下载失败 {file_name}: {e}")
                    if staged_path.exists():
                        staged_path.unlink()
                    try:
                        progress.remove_task(task_id)
                    except Exception:
                        pass
                    return False, dest, expected_size

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(download_repair, d): d for d in repair_needed}
                for future in as_completed(futures):
                    success, dest, size = future.result()
                    if success:
                        repair_count += 1
                        _emit_progress_log(progress, "INFO", f"修复成功: {dest}")
                    else:
                        fail_count += 1
                        _emit_progress_log(progress, "ERROR", f"修复失败: {dest}")
                    progress.update(overall_task, advance=size)

        logger.info(f"修复完成: 成功={repair_count}, 失败={fail_count}")
        if fail_count == 0:
            self._update_local_version(target_version or index_data)
            return True
        return False

    def _cleanup_cache_dir(self) -> None:
        """清理缓存中的临时目录（patch_temp、回退下载、修复下载等）"""
        temp_subdirs = ["patch_temp", "full_download_temp", "repair_download_temp"]
        cleaned = 0
        for name in temp_subdirs:
            subdir = self.cache_dir / name
            if subdir.exists():
                shutil.rmtree(subdir, ignore_errors=True)
                cleaned += 1
        if cleaned:
            logger.debug(f"已清理 {cleaned} 个缓存临时目录")

    def _find_resource_base(self) -> Optional[str]:
        """从 indexFile.json 或 API 配置获取资源路径前缀"""
        download_dir = self.game_folder / ".incremental_download"
        index_file = download_dir / "indexFile.json"
        cache_index_file = self.cache_dir / "indexFile.json"

        if index_file.exists() or cache_index_file.exists():
            if not index_file.exists():
                index_file = cache_index_file
            try:
                data = json.loads(index_file.read_text())
                resources = data.get("resource", [])
                if resources:
                    from_folder = resources[0].get("fromFolder", "")
                    if from_folder:
                        return from_folder.rstrip("/")
            except Exception:
                pass

        patch_info = self._find_matching_patch()
        if patch_info:
            base_url = patch_info.get("baseUrl", "")
            if base_url:
                return base_url.rstrip("/")

        default_base = self.default_config.get("baseUrl", "")
        if default_base:
            return default_base.rstrip("/")

        return None

    def _download_and_verify_complete(
        self,
        url: str,
        dest: Path,
        expected_size: int,
        expected_md5: str,
        progress: Optional[Progress] = None,
        overall_task_id: Optional[TaskID] = None,
    ) -> bool:
        """下载完整文件并验证 MD5，支持进度条"""
        dest.parent.mkdir(parents=True, exist_ok=True)

        task_id = None
        if progress:
            task_id = progress.add_task(description=dest.name, total=expected_size)
            color = RAINBOW_COLORS[task_id % len(RAINBOW_COLORS)]
            progress.update(task_id, description=f"[{color}]{dest.name}[/{color}]")

        temp_file = dest.with_suffix(dest.suffix + ".temp")
        headers = {"User-Agent": "WW-Manager/2.0"}

        try:
            response = requests.get(url, headers=headers, timeout=60, stream=True)
            response.raise_for_status()

            with open(temp_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    f.write(chunk)
                    if progress and task_id is not None:
                        chunk_len = len(chunk)
                        progress.update(task_id, advance=chunk_len)
                        if overall_task_id is not None:
                            progress.update(overall_task_id, advance=chunk_len)

            if progress and task_id is not None:
                progress.remove_task(task_id)

            shutil.move(temp_file, dest)

            actual_size = dest.stat().st_size
            if actual_size != expected_size:
                _emit_progress_log(progress, "ERROR", f"文件大小不匹配: {dest.name}")
                dest.unlink()
                return False

            actual_md5 = _calculate_file_md5(dest)
            if actual_md5 != expected_md5:
                _emit_progress_log(progress, "ERROR", f"文件 MD5 不匹配: {dest.name}")
                dest.unlink()
                return False

            return True

        except Exception as e:
            _emit_progress_log(progress, "ERROR", f"下载失败 {dest.name}: {e}")
            if temp_file.exists():
                temp_file.unlink()
            if progress and task_id is not None:
                progress.remove_task(task_id)
            return False

    def _download_and_verify(
        self,
        url: str,
        dest: Path,
        expected_size: int,
        expected_md5: str,
        error_callback: Optional[Callable[[str], None]] = None,
        suppress_success_log: bool = False,
    ) -> bool:
        """下载文件并验证 MD5"""

        def emit_error(msg: str):
            if error_callback:
                error_callback(msg)
            else:
                logger.error(msg)

        try:
            headers = {"User-Agent": "WW-Manager/2.0"}
            response = requests.get(url, headers=headers, timeout=60, stream=True)
            response.raise_for_status()

            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    f.write(chunk)

            actual_size = dest.stat().st_size
            if actual_size != expected_size:
                emit_error(f"文件大小不匹配: {dest.name} (期望 {expected_size}, 实际 {actual_size})")
                dest.unlink()
                return False

            actual_md5 = _calculate_file_md5(dest)
            if actual_md5 != expected_md5:
                emit_error(f"文件 MD5 不匹配: {dest.name}")
                dest.unlink()
                return False

            if not suppress_success_log:
                logger.info(f"修复成功: {dest.name}")
            return True

        except Exception as e:
            emit_error(f"下载失败 {dest.name}: {e}")
            if dest.exists():
                dest.unlink()
            return False

    def _update_local_version(self, version_or_data):
        """更新本地版本，可接收版本字符串或 indexFile.json 数据"""
        if isinstance(version_or_data, dict):
            new_version = version_or_data.get("version") or version_or_data.get("to_version")
            if not new_version:
                group_infos = version_or_data.get("groupInfos", [])
                if not group_infos:
                    logger.warning("无法获取 groupInfos 信息")
                    return
                krpdiff_name = Path(group_infos[0]["dest"]).stem
                parts = krpdiff_name.split("_")
                new_version = parts[1] if len(parts) >= 2 else None
        else:
            new_version = version_or_data

        if not new_version:
            logger.warning("无法获取新版本号")
            return

        cfg_path = self.game_folder / "launcherDownloadConfig.json"
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text())
                data["version"] = new_version
                cfg_path.write_text(json.dumps(data, indent=4))
                logger.info(f"本地版本已更新: {new_version}")
            except Exception as e:
                logger.error(f"更新本地版本失败: {e}")
