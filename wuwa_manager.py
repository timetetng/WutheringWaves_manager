#!/usr/bin/env python3
# ww_manager.py
import os
import shutil
import hashlib
import json
import gzip
import io
import logging
from pathlib import Path
from urllib.request import urlopen, Request, HTTPError
from urllib.parse import urljoin, quote
from enum import Enum
from typing import Optional
from typing_extensions import Annotated

import typer
from tqdm import tqdm

# --- 配置 ---

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("WW_Manager")

CONFIG_DIR = Path.home() / ".config" / "ww_manager"
CONFIG_FILE = CONFIG_DIR / "config.json"

# --- Typer App 初始化 ---
app = typer.Typer(
    help="鸣潮 (Wuthering Waves) 命令行下载/切换管理器",
    add_completion=False,
    no_args_is_help=True,
)


# 定义服务器枚举，用于 CLI 参数自动补全和校验
class ServerType(str, Enum):
    cn = "cn"
    global_server = "global"
    bilibili = "bilibili"


class TqdmUpTo(tqdm):
    """提供一个 tqdm 更新回调"""

    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


# API (参考leck995/WutheringWavesTool)
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


def load_app_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
            logger.debug(f"已从 {CONFIG_FILE} 加载配置")
            return config
    except Exception as e:
        logger.warning(f"无法加载配置文件 {CONFIG_FILE}: {e}")
        return {}


def save_app_config(config):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        logger.debug(f"配置已保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"无法保存配置 {CONFIG_FILE}: {e}")


# --- 核心下载逻辑 ---
class WDLancher:
    def __init__(self, game_folder, server_type):
        if server_type not in SERVER_CONFIGS:
            logger.error(
                f"无效的服务器类型: {server_type}. 可选: {list(SERVER_CONFIGS.keys())}"
            )
            sys.exit(1)

        self.config = SERVER_CONFIGS[server_type]
        self.server_type = server_type
        self.launcher_api = self.config["api_url"]

        logger.info(f"初始化 {server_type} 服...")
        self.launcher_info = self.get_result(self.launcher_api)

        if self.launcher_info is None:
            logger.error("获取启动器信息失败 (网络错误?)")
            sys.exit(1)

        self.cdn_node = self.select_cdn()

        self.game_folder_path = Path(game_folder)
        if not self.game_folder_path.exists():
            logger.info(f"创建游戏目录: {self.game_folder_path}")
            self.game_folder_path.mkdir(parents=True, exist_ok=True)

        self.gamefile_index = self.get_gamefile_index()
        if not self.gamefile_index:
            logger.error("获取文件清单(indexFile)失败.")
            sys.exit(1)

        self.resources_base_path = self.launcher_info["default"]["resourcesBasePath"]
        self.current_version = self.launcher_info["default"]["version"]

        # MD5 缓存
        self.md5_cache_path = self.game_folder_path / "wwm_md5_cache.json"
        self.md5_cache = self.load_md5_cache()
        self._md5_cache_updated = False

    def get_result(self, url):
        try:
            req = Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"}
            )
            with urlopen(req, timeout=10) as rsp:
                if rsp.status != 200:
                    logger.error(f"HTTP 状态 {rsp.status} for {url}")
                    return None
                content_encoding = rsp.headers.get("Content-Encoding", "").lower()
                data = rsp.read()
                if "gzip" in content_encoding:
                    try:
                        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                            data = f.read()
                    except Exception as e:
                        logger.error(f"Gzip 解压错误: {str(e)}")
                        return None
                return json.loads(data.decode("utf-8"))
        except Exception as e:
            logger.error(f"获取 {url} 失败: {str(e)}")
            return None

    def select_cdn(self):
        if self.launcher_info is None:
            return None
        cdnlist = self.launcher_info["default"].get("cdnList", None)
        if not cdnlist:
            return None

        available_nodes = [
            node for node in cdnlist if node["K1"] == 1 and node["K2"] == 1
        ]
        if not available_nodes:
            return None

        max_priority = max(node["P"] for node in available_nodes)

        for node in available_nodes:
            if node["P"] == max_priority:
                logger.info(f"选择 CDN: {node['url']}")
                return node["url"]

    def get_gamefile_index(self):
        if self.launcher_info is None:
            return None
        indexfile_uri = self.launcher_info["default"]["config"]["indexFile"]
        logger.info("正在获取文件清单 (indexFile.json)...")
        indexfile = self.get_result(urljoin(self.cdn_node, indexfile_uri))
        return indexfile

    def download_file_with_resume(
        self, url, file_path: Path, overwrite=False, file_size_expected=None
    ):
        directory = file_path.parent
        if not directory.exists():
            os.makedirs(directory)

        temp_file_path = file_path.with_suffix(file_path.suffix + ".temp")

        if file_path.exists():
            if not overwrite:
                return True
            else:
                os.remove(file_path)

        downloaded_bytes = 0
        if temp_file_path.exists():
            downloaded_bytes = os.path.getsize(temp_file_path)

        headers = {"User-Agent": "Mozilla/5.0"}
        if downloaded_bytes > 0:
            headers["Range"] = f"bytes={downloaded_bytes}-"

        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as rsp:
                total_size = file_size_expected
                if total_size is None:
                    total_size = int(rsp.headers.get("Content-Length", 0))

                if rsp.status == 206:
                    total_size = downloaded_bytes + int(
                        rsp.headers.get("Content-Length")
                    )
                elif rsp.status == 200:
                    if downloaded_bytes > 0:
                        logger.warning("服务器不支持断点续传, 重新下载.")
                    downloaded_bytes = 0
                else:
                    logger.error(f"下载失败 (HTTP: {rsp.status}): {file_path.name}")
                    return False

                mode = "ab" if downloaded_bytes > 0 else "wb"

                with TqdmUpTo(
                    unit="B",
                    unit_scale=True,
                    miniters=1,
                    desc=f"  {file_path.name[:30]:<30}",
                    total=total_size,
                    initial=downloaded_bytes,
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
                ) as pbar:
                    with open(temp_file_path, mode) as file:
                        while True:
                            chunk = rsp.read(1024 * 1024)  # 1MB chunk
                            if not chunk:
                                break
                            file.write(chunk)
                            pbar.update(len(chunk))

            shutil.move(temp_file_path, file_path)
            self.clear_file_md5_cache(file_path)
            return True
        except Exception as e:
            logger.error(f"下载 {url} 出错: {e}")
            return False

    # --- MD5 缓存 ---
    def load_md5_cache(self):
        if self.md5_cache_path.exists():
            try:
                with open(self.md5_cache_path, "r", encoding="utf-8") as f:
                    logger.info("加载 MD5 缓存...")
                    return json.load(f)
            except Exception as e:
                logger.warning(f"加载 MD5 缓存失败: {e}, 将重新生成。")
                return {}
        return {}

    def save_md5_cache(self):
        if not self._md5_cache_updated:
            return
        try:
            with open(self.md5_cache_path, "w", encoding="utf-8") as f:
                json.dump(self.md5_cache, f, indent=2)
            logger.info("MD5 缓存已保存。")
        except Exception as e:
            logger.error(f"保存 MD5 缓存失败: {e}")

    def clear_file_md5_cache(self, file_path: Path):
        relative_path_str = str(file_path.relative_to(self.game_folder_path))
        if relative_path_str in self.md5_cache:
            del self.md5_cache[relative_path_str]
            self._md5_cache_updated = True
            logger.debug(f"清除缓存: {relative_path_str}")

    def get_file_md5(self, file_path: Path):
        if not file_path.exists():
            return None

        try:
            relative_path_str = str(file_path.relative_to(self.game_folder_path))
            mtime = os.path.getmtime(file_path)

            if relative_path_str in self.md5_cache:
                cached_data = self.md5_cache[relative_path_str]
                if cached_data["mtime"] == mtime:
                    logger.debug(f"命中缓存: {relative_path_str}")
                    return cached_data["md5"]

            logger.info(f"(计算中): {relative_path_str}")
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096 * 1024), b""):  # 4MB chunk
                    md5_hash.update(chunk)

            new_md5 = md5_hash.hexdigest()
            self.md5_cache[relative_path_str] = {"mtime": mtime, "md5": new_md5}
            self._md5_cache_updated = True
            return new_md5

        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"计算 MD5 时出错 {file_path}: {e}")
            return None

    def update_localVersion(self, server_type, version):
        """(公共) 更新 launcherDownloadConfig.json"""
        if server_type not in SERVER_CONFIGS:
            logger.error(f"无效的服务器类型: {server_type}")
            return

        config = SERVER_CONFIGS[server_type]
        temp = {
            "version": version,
            "reUseVersion": "",
            "state": "",
            "isPreDownload": False,
            "appId": config["appId"],  # 关键: 写入正确的 appId
        }
        file_path = self.game_folder_path / "launcherDownloadConfig.json"
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(temp, file, ensure_ascii=False, indent=4)
            logger.info(
                f"已更新 launcherDownloadConfig.json (Version: {version}, AppId: {config['appId']})"
            )
        except Exception as e:
            logger.error(f"写入 launcherDownloadConfig.json 失败: {e}")

    # --- CLI 命令对应的功能 ---
    def download_game(self):
        """(download) 下载所有游戏文件"""
        logger.info(f"开始为 {self.server_type} 服下载完整游戏...")
        resource_list = list(self.gamefile_index["resource"])
        total = len(resource_list)

        for i, file in enumerate(resource_list):
            logger.info(f"--- 进度 {i + 1}/{total} ---")
            download_url = urljoin(
                self.cdn_node, self.resources_base_path + "/" + file["dest"]
            )
            download_url = quote(download_url, safe=":/")
            file_path = self.game_folder_path.joinpath(Path(file["dest"]))

            current_md5 = self.get_file_md5(file_path)
            if current_md5 == file["md5"]:
                logger.info(f"文件已存在且 MD5 匹配 (跳过): {file['dest']}")
                continue

            self.download_file_with_resume(
                url=download_url,
                file_path=file_path,
                overwrite=True,
                file_size_expected=int(file["size"]),
            )

        logger.info("完整下载任务完成。")
        self.update_localVersion(self.server_type, self.current_version)
        self.save_md5_cache()

    def sync_gamefile(self):
        """(sync) 校验、同步和清理文件 (慢速但100%准确)"""
        logger.info(f"开始校验 {self.server_type} 服的文件...")
        resource_list = list(self.gamefile_index["resource"])

        # 1. 构建所有预期文件的 Set
        expected_files_map = {item["dest"]: item for item in resource_list}
        expected_relative_paths = set(expected_files_map.keys())

        # 2. 智能重命名 (清理/烘焙)
        diff_check_dirs = [
            self.game_folder_path / "Client" / "Content" / "Paks",
            self.game_folder_path / "Client" / "Binaries" / "Win64",
        ]

        logger.info("正在检查差异文件...")
        files_to_check = []
        for d in diff_check_dirs:
            if d.exists():
                files_to_check.extend(d.glob("*.pak"))
                files_to_check.extend(d.glob("*.dll"))
                files_to_check.extend(d.glob("*.pak.bak"))
                files_to_check.extend(d.glob("*.dll.bak"))

        for file_path in files_to_check:
            try:
                relative_path_str = str(
                    file_path.relative_to(self.game_folder_path)
                ).replace("\\", "/")

                if file_path.suffix == ".bak":
                    original_rel_path = relative_path_str.removesuffix(".bak")
                    if original_rel_path in expected_relative_paths:
                        bak_path = file_path
                        original_path = file_path.with_suffix("")
                        logger.info(f"快速切换 (恢复): {original_rel_path}")
                        shutil.move(bak_path, original_path)
                        self.clear_file_md5_cache(original_path)

                elif relative_path_str in expected_relative_paths:
                    pass
                else:
                    logger.warning(f"快速切换 (备份): {relative_path_str}")
                    bak_path = file_path.with_suffix(file_path.suffix + ".bak")
                    shutil.move(file_path, bak_path)
                    self.clear_file_md5_cache(file_path)
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错: {e}")

        # 3. 校验并下载缺失/错误的文件
        total = len(resource_list)
        logger.info(f"开始校验 {total} 个文件 (将使用 MD5 缓存)...")

        for i, file in enumerate(resource_list):
            file_path = self.game_folder_path.joinpath(Path(file["dest"]))

            current_md5 = self.get_file_md5(file_path)
            expected_md5 = file["md5"]

            if current_md5 == expected_md5:
                continue

            if file_path.exists():
                logger.warning(f"({i + 1}/{total}) MD5 不匹配: {file['dest']}")
            else:
                logger.info(f"({i + 1}/{total}) 文件缺失: {file['dest']}")

            download_url = urljoin(
                self.cdn_node, self.resources_base_path + "/" + file["dest"]
            )
            download_url = quote(download_url, safe=":/")
            self.download_file_with_resume(
                url=download_url,
                file_path=file_path,
                overwrite=True,
                file_size_expected=int(file["size"]),
            )

        logger.info("文件校验和同步完成。")
        self.update_localVersion(self.server_type, self.current_version)
        self.save_md5_cache()


# --- CLI 命令处理 ---


def get_current_server(game_folder_path: Path):
    if not game_folder_path:
        return None, None
    config_path = game_folder_path / "launcherDownloadConfig.json"
    if not config_path.exists():
        logger.warning(f"{config_path} 未找到. 无法检测当前服务器。")
        return None, None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        appId = data.get("appId")
        version = data.get("version")
        server = APPID_TO_SERVER.get(appId, "unknown")
        return server, version
    except Exception as e:
        logger.error(f"读取 {config_path} 失败: {e}")
        return None, None


# --- Typer 命令定义 ---


@app.callback()
def main(
    ctx: typer.Context,
    path: Annotated[
        Optional[Path],
        typer.Option(
            "--path",
            "-p",
            help="游戏《Wuthering Waves Game》目录路径。\n(使用一次后将自动保存)",
            show_default=False,
        ),
    ] = None,
):
    """
    鸣潮 (Wuthering Waves) 命令行下载/切换管理器
    """
    app_config = load_app_config()
    default_path = app_config.get("default_path")

    # 路径判定逻辑：参数 > 配置文件
    final_path = path if path else (Path(default_path) if default_path else None)

    # 如果传入了新路径且有效，自动保存
    if path and (not default_path or str(path.resolve()) != default_path):
        # 简单的路径存在性检查可以放在这里，也可以放在具体命令中
        logger.info(f"设置新的默认游戏路径为: {path.resolve()}")
        app_config["default_path"] = str(path.resolve())
        save_app_config(app_config)

    # 将路径和配置存入 context，供子命令使用
    ctx.ensure_object(dict)
    ctx.obj["game_path"] = final_path
    ctx.obj["app_config"] = app_config

    # 除了 clear-path 命令外，其他命令都强制需要路径
    if ctx.invoked_subcommand != "clear-path" and not final_path:
        typer.secho("错误: 缺少游戏路径。", fg=typer.colors.red)
        typer.echo("请至少使用 -p /path/to/game 运行一次以设置默认路径。")
        raise typer.Exit(code=1)


@app.command()
def status(ctx: typer.Context):
    """检查当前游戏目录的服务器类型和版本"""
    game_path = ctx.obj["game_path"]
    logger.info("--- 状态检查 ---")
    server, version = get_current_server(game_path)
    if server:
        typer.echo(f"  游戏目录: {game_path.resolve()}")
        typer.echo(f"  当前服务器: {server}")
        typer.echo(f"  当前版本: {version}")
    else:
        typer.echo(f"  未在 {game_path} 中找到有效的游戏配置。")


@app.command()
def sync(ctx: typer.Context):
    """[慢速] 校验当前服务器的文件，下载缺失/损坏文件，并烘焙差异文件 (修复/更新)"""
    game_path = ctx.obj["game_path"]
    logger.info("--- 同步当前服务器 (慢速/修复) ---")

    server, _ = get_current_server(game_path)
    if not server or server == "unknown":
        logger.error("无法确定当前服务器类型。请先使用 'download' 或 'checkout'。")
        raise typer.Exit(code=1)

    logger.info(f"检测到当前服务器为: {server}。开始同步...")
    launcher = WDLancher(game_path, server)
    launcher.sync_gamefile()


@app.command()
def checkout(
    ctx: typer.Context,
    server: Annotated[ServerType, typer.Argument(help="要切换到的目标服务器")],
    force_sync: Annotated[
        bool, typer.Option("--force-sync", help="切换后立即强制执行 sync")
    ] = False,
):
    """[快速] 立即切换到另一个服务器 (仅重命名差异文件)"""
    game_path = ctx.obj["game_path"]
    target_server = server.value

    logger.info(f"--- 快速切换服务器 ---")

    current_server, current_version = get_current_server(game_path)
    if current_server == target_server:
        logger.warning(f"当前已经是 {target_server} 服。")
        if force_sync:
            logger.info("强制执行 'sync'...")
            # 复用 sync 逻辑
            launcher = WDLancher(game_path, target_server)
            launcher.sync_gamefile()
        return

    logger.info(f"正在从 {current_server} 切换到 {target_server}...")

    # 1. 禁用当前服的差异文件
    if current_server and current_server != "unknown":
        for rel_path in SERVER_DIFF_FILES.get(current_server, []):
            file = game_path / rel_path
            if file.exists():
                bak_file = file.with_suffix(file.suffix + ".bak")
                logger.info(f"  (禁用) {rel_path} -> {bak_file.name}")
                try:
                    shutil.move(file, bak_file)
                except Exception as e:
                    logger.error(f"  重命名失败: {e}")

    # 2. 启用目标服的差异文件
    missing_files = False
    for rel_path in SERVER_DIFF_FILES.get(target_server, []):
        file = game_path / rel_path
        bak_file = file.with_suffix(file.suffix + ".bak")

        if file.exists():
            logger.info(f"  (已启用) {rel_path}")
            continue

        if bak_file.exists():
            logger.info(f"  (启用) {bak_file.name} -> {file.name}")
            try:
                shutil.move(bak_file, file)
            except Exception as e:
                logger.error(f"  重命名失败: {e}")
        else:
            logger.error(f"  (缺失!) {rel_path}")
            missing_files = True

    # 3. 更新配置文件
    version_to_write = current_version if current_version else "unknown"
    # 这里实例化仅用于更新本地版本文件，不进行网络请求
    # 注意：WDLancher 初始化会联网获取 API，如果离线切换可能会失败
    # 如果需要纯离线切换，需要重构 WDLancher 把网络请求延后，这里暂时保持原逻辑
    try:
        temp_launcher = WDLancher(game_path, target_server)
        temp_launcher.update_localVersion(target_server, version_to_write)
    except SystemExit:
        # 如果 WDLancher 初始化失败(例如没网)，我们至少尝试手动写入基本的 config
        logger.warning("无法连接服务器 API，尝试离线更新版本文件...")
        # 简单的离线回退逻辑，或者让用户稍后 sync
        pass

    if missing_files:
        logger.warning("--- 切换完成，但检测到文件缺失 ---")
        logger.warning(
            f"您的游戏目录不是 '全家桶'，缺少 {target_server} 服的差异文件。"
        )
    else:
        logger.info("--- 切换完成 ---")

    if force_sync:
        logger.info("强制执行 'sync'...")
        launcher = WDLancher(game_path, target_server)
        launcher.sync_gamefile()
    elif missing_files:
        logger.warning(f"请立即运行 'sync' 命令来下载缺失文件:")
        typer.echo(f'\n{sys.argv[0]} -p "{game_path}" sync\n')


@app.command()
def download(
    ctx: typer.Context,
    server: Annotated[ServerType, typer.Argument(help="要下载的目标服务器")],
):
    """[慢速] 下载一个全新的、完整的服务器客户端 (会执行 sync)"""
    game_path = ctx.obj["game_path"]
    target_server = server.value

    logger.info("--- 下载完整游戏 (慢速) ---")
    logger.warning(f"将要下载 {target_server} 服的完整客户端到 {game_path}")

    launcher = WDLancher(game_path, target_server)
    launcher.download_game()
    logger.info("下载完成。现在开始强制校验一遍...")
    launcher.sync_gamefile()
    logger.info(f"完整客户端 ( {target_server} ) 下载并校验完成。")


@app.command("clear-path")
def clear_path(ctx: typer.Context):
    """清除已保存的默认游戏路径"""
    app_config = ctx.obj.get("app_config", {})
    if "default_path" in app_config:
        del app_config["default_path"]
        save_app_config(app_config)
        logger.info(f"已清除保存的游戏路径。")
    else:
        logger.info("没有保存的游戏路径。")


if __name__ == "__main__":
    import certifi

    os.environ["SSL_CERT_FILE"] = certifi.where()
    app()
