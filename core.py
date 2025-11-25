# core.py
import os
import shutil
import hashlib
import json
import gzip
import logging
import time
import threading
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any

from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    DownloadColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
    TaskID,
)
from config import SERVER_CONFIGS, SERVER_DIFF_FILES

logger = logging.getLogger("WW_Manager")


# --- 自定义异常 ---
class WWError(Exception):
    """基础异常类"""

    pass


class NetworkError(WWError):
    """网络相关错误"""

    pass


class ConfigError(WWError):
    """配置或路径错误"""

    pass


# --- MD5 缓存管理器 ---
class MD5Cache:
    def __init__(self, cache_path: Path, game_root: Path):
        self.cache_path = cache_path
        self.game_root = game_root
        self.cache: Dict[str, Dict[str, Any]] = self._load()
        self._updated = False
        self._lock = threading.Lock()

    def _load(self) -> Dict[str, Any]:
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save(self) -> None:
        if not self._updated:
            return
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
            logger.debug("MD5 缓存已保存")
        except Exception as e:
            logger.error(f"保存 MD5 缓存失败: {e}")

    def get(self, file_path: Path) -> Optional[str]:
        if not file_path.exists():
            return None

        try:
            rel_path = str(file_path.relative_to(self.game_root)).replace("\\", "/")
        except ValueError:
            rel_path = file_path.name

        mtime = os.path.getmtime(file_path)

        with self._lock:
            if rel_path in self.cache:
                data = self.cache[rel_path]
                if data["mtime"] == mtime:
                    return data["md5"]

        new_md5 = self._calculate_md5(file_path)
        if new_md5:
            with self._lock:
                self.cache[rel_path] = {"mtime": mtime, "md5": new_md5}
                self._updated = True
        return new_md5

    def _calculate_md5(self, file_path: Path) -> Optional[str]:
        logger.debug(f"计算 MD5: {file_path.name}")
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096 * 1024), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"计算 MD5 错误 {file_path}: {e}")
            return None

    def clear(self, file_path: Path) -> None:
        try:
            rel_path = str(file_path.relative_to(self.game_root)).replace("\\", "/")
            with self._lock:
                if rel_path in self.cache:
                    del self.cache[rel_path]
                    self._updated = True
        except ValueError:
            pass


# --- 核心管理器 ---
class WGameManager:
    def __init__(self, game_folder: Path, server_type: str):
        if server_type not in SERVER_CONFIGS:
            raise ConfigError(f"无效的服务器类型: {server_type}")

        self.game_folder = game_folder.resolve()
        self.server_type = server_type
        self.config = SERVER_CONFIGS[server_type]

        self.md5_cache = MD5Cache(
            self.game_folder / "wwm_md5_cache.json", self.game_folder
        )

        self._launcher_info = None
        self._cdn_node = None
        self._game_index = None

    @property
    def launcher_info(self):
        if not self._launcher_info:
            logger.info(f"正在获取 {self.server_type} 服配置...")
            self._launcher_info = self._http_get_json(self.config["api_url"])
            if not self._launcher_info:
                raise NetworkError("无法获取启动器配置信息")
        return self._launcher_info

    @property
    def cdn_node(self):
        if not self._cdn_node:
            nodes = self.launcher_info["default"].get("cdnList", [])
            valid_nodes = [n for n in nodes if n.get("K1") == 1 and n.get("K2") == 1]
            if not valid_nodes:
                raise NetworkError("没有可用的 CDN 节点")
            best = max(valid_nodes, key=lambda x: x["P"])
            self._cdn_node = best["url"]
            logger.info(f"使用 CDN: {self._cdn_node}")
        return self._cdn_node

    @property
    def game_index(self):
        if not self._game_index:
            uri = self.launcher_info["default"]["config"]["indexFile"]
            url = urljoin(self.cdn_node, uri)
            logger.info("下载文件清单 (Index)...")
            self._game_index = self._http_get_json(url)
            if not self._game_index:
                raise NetworkError("无法下载文件清单")
        return self._game_index

    def _http_get_json(self, url: str) -> Optional[Any]:
        try:
            req = Request(
                url, headers={"User-Agent": "WW-Manager/2.0", "Accept-Encoding": "gzip"}
            )
            with urlopen(req, timeout=10) as rsp:
                if rsp.status != 200:
                    return None
                data = rsp.read()
                if "gzip" in rsp.headers.get("Content-Encoding", "").lower():
                    data = gzip.decompress(data)
                return json.loads(data)
        except Exception as e:
            logger.error(f"HTTP 请求失败 {url}: {e}")
            return None

    def _download_file(
        self,
        url: str,
        dest: Path,
        expected_size: int,
        progress: Optional[Progress] = None,
        overall_task_id: Optional[TaskID] = None,
    ) -> bool:
        """带重试的单文件下载，使用 Rich Progress"""
        dest.parent.mkdir(parents=True, exist_ok=True)

        # 注册单个文件的子任务
        task_id = None
        if progress:
            task_id = progress.add_task(description=dest.name, total=expected_size)

        temp_file = dest.with_suffix(dest.suffix + ".temp")
        headers = {"User-Agent": "WW-Manager/2.0"}

        retries = 3
        success = False

        for attempt in range(retries):
            try:
                resume_byte = 0
                if temp_file.exists():
                    resume_byte = temp_file.stat().st_size

                # 如果已完成，更新进度条并跳过
                if resume_byte == expected_size:
                    if progress and task_id is not None:
                        progress.update(task_id, completed=expected_size)
                        if overall_task_id is not None:
                            pass
                    success = True
                    break

                if resume_byte > 0:
                    headers["Range"] = f"bytes={resume_byte}-"
                    # 更新子进度条到断点位置
                    if progress and task_id is not None:
                        progress.update(task_id, completed=resume_byte)

                mode = "ab" if resume_byte > 0 else "wb"

                req = Request(url, headers=headers)
                with urlopen(req, timeout=15) as rsp:
                    if rsp.status not in (200, 206):
                        raise NetworkError(f"HTTP {rsp.status}")

                    with open(temp_file, mode) as f:
                        while True:
                            chunk = rsp.read(1024 * 256)
                            if not chunk:
                                break
                            f.write(chunk)

                            # 更新界面
                            if progress:
                                chunk_len = len(chunk)
                                if task_id is not None:
                                    progress.update(task_id, advance=chunk_len)
                                if overall_task_id is not None:
                                    progress.update(overall_task_id, advance=chunk_len)

                if temp_file.stat().st_size == expected_size:
                    success = True
                    break
                else:
                    # 大小不对，重试
                    pass

            except Exception as e:
                if attempt == retries - 1:
                    # 只有最后一次失败才记录日志，避免进度条乱掉
                    if progress:
                        progress.console.log(f"[red]下载失败 {dest.name}: {e}[/red]")
                    return False
                time.sleep(1 + attempt)

        if success:
            shutil.move(temp_file, dest)
            self.md5_cache.clear(dest)

        # 移除子任务，保持界面整洁
        if progress and task_id is not None:
            progress.remove_task(task_id)

        return success

    def _batch_download(self, tasks: List[dict]):
        if not tasks:
            logger.info("没有文件需要下载")
            return

        total_size = sum(t["size"] for t in tasks)
        logger.info(
            f"准备下载 {len(tasks)} 个文件，总大小: {total_size / 1024 / 1024:.2f} MB"
        )

        max_workers = 8

        # 使用 Rich Progress 上下文
        progress = Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            expand=True,
        )

        with progress:
            # 总任务
            overall_task = progress.add_task("Total Download", total=total_size)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for task in tasks:
                    future = executor.submit(
                        self._download_file,
                        task["url"],
                        task["path"],
                        task["size"],
                        progress,
                        overall_task,
                    )
                    futures.append(future)

                for f in as_completed(futures):
                    if not f.result():
                        progress.console.log("[red]有文件下载失败，请重试 sync[/red]")

    def sync_files(self, force_check_md5=False):
        res_base = self.launcher_info["default"]["resourcesBasePath"]
        res_list = self.game_index["resource"]

        tasks = []

        logger.info("正在校验文件...")
        for item in res_list:
            dest_path = self.game_folder / item["dest"]
            expected_md5 = item["md5"]
            expected_size = int(item["size"])

            need_download = False
            if not dest_path.exists():
                need_download = True
            elif force_check_md5:
                if self.md5_cache.get(dest_path) != expected_md5:
                    need_download = True
            elif dest_path.stat().st_size != expected_size:
                need_download = True

            if need_download:
                url = urljoin(self.cdn_node, f"{res_base}/{item['dest']}")
                tasks.append(
                    {
                        "url": quote(url, safe=":/"),
                        "path": dest_path,
                        "size": expected_size,
                    }
                )

        if tasks:
            self._batch_download(tasks)
            self.md5_cache.save()
            self._update_local_config()
        else:
            logger.info("所有文件校验通过，无需下载。")

    def download_full(self):
        self.sync_files(force_check_md5=False)

    def checkout(self, target_server: str, force_sync: bool = False):
        # 1. 禁用当前差异文件
        for _, files in SERVER_DIFF_FILES.items():
            for f_rel in files:
                f = self.game_folder / f_rel
                if f.exists():
                    f.rename(f.with_suffix(f.suffix + ".bak"))
                    self.md5_cache.clear(f)

        # 2. 启用目标差异文件
        missing = False
        for f_rel in SERVER_DIFF_FILES.get(target_server, []):
            f = self.game_folder / f_rel
            bak = f.with_suffix(f.suffix + ".bak")

            if bak.exists():
                bak.rename(f)
                self.md5_cache.clear(f)
            elif f.exists():
                pass
            else:
                missing = True
                # 我发现这玩意没啥用
                # logger.warning(f"缺失差异文件: {f_rel}")

        # 3. 更新配置
        self.server_type = target_server
        try:
            self._update_local_config()
        except Exception:
            pass

        if missing or force_sync:
            logger.info("检测到缺失文件或强制同步，开始同步...")
            self.sync_files(force_check_md5=True)

    def _update_local_config(self):
        v = self.launcher_info["default"]["version"]
        cfg = {"version": v, "appId": self.config["appId"], "group": "default"}
        self.game_folder.mkdir(parents=True, exist_ok=True)
        with open(self.game_folder / "launcherDownloadConfig.json", "w") as f:
            json.dump(cfg, f, indent=4)
        logger.info(f"已更新本地配置: {self.server_type} ({v})")
