#!/usr/bin/env python3
# ww_manager.py
import sys
import os
import shutil
import hashlib
import json
import gzip
import io
import argparse
import logging
from pathlib import Path
from urllib.request import urlopen, Request, HTTPError
from urllib.parse import urljoin, quote
from tqdm import tqdm

# --- 配置 ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("WW_Manager")

CONFIG_DIR = Path.home() / ".config" / "ww_manager"
CONFIG_FILE = CONFIG_DIR / "config.json"

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
        "appId": "10003"
    },
    "global": {
        "api_url": "https://prod-alicdn-gamestarter.kurogame.com/launcher/game/G153/50004_obOHXFrFanqsaIEOmuKroCcbZkQRBC7c/index.json",
        "appId": "50004"
    },
    "bilibili": {
        "api_url": "https://prod-cn-alicdn-gamestarter.kurogame.com/launcher/game/G152/10004_j5GWFuUFlb8N31Wi2uS3ZAVHcb7ZGN7y/index.json",
        "appId": "10004"
    }
}
APPID_TO_SERVER = {v["appId"]: k for k, v in SERVER_CONFIGS.items()}
SERVER_DIFF_FILES = {
    "cn": [
        "Client/Binaries/Win64/kuro_login.dll",
        "Client/Content/Paks/pakchunk1-Kuro-Win64-Shipping.pak"
    ],
    "bilibili": [
        "Client/Binaries/Win64/bilibili_sdk.dll",
        "Client/Content/Paks/pakchunk1-Bilibili-Win64-Shipping.pak"
    ],
    "global": [
        "Client/Binaries/Win64/kuro_login.dll", 
        "Client/Content/Paks/pakchunk1-Kuro-Win64-Shipping.pak"
    ]
}


def load_app_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            logger.debug(f"已从 {CONFIG_FILE} 加载配置")
            return config
    except Exception as e:
        logger.warning(f"无法加载配置文件 {CONFIG_FILE}: {e}")
        return {}

def save_app_config(config):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        logger.debug(f"配置已保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"无法保存配置 {CONFIG_FILE}: {e}")


# --- 核心下载逻辑 ---
class WDLancher:
    
    def __init__(self, game_folder, server_type):
        if server_type not in SERVER_CONFIGS:
            logger.error(f"无效的服务器类型: {server_type}. 可选: {list(SERVER_CONFIGS.keys())}")
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
            
        self.resources_base_path = self.launcher_info['default']['resourcesBasePath']
        self.current_version = self.launcher_info['default']['version']

        # MD5 缓存
        self.md5_cache_path = self.game_folder_path / "wwm_md5_cache.json"
        self.md5_cache = self.load_md5_cache()
        self._md5_cache_updated = False 

    def get_result(self, url):
        try:
            req = Request(url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept-Encoding': 'gzip'
            })
            with urlopen(req, timeout=10) as rsp:
                if rsp.status != 200:
                    logger.error(f"HTTP 状态 {rsp.status} for {url}")
                    return None
                content_encoding = rsp.headers.get('Content-Encoding', '').lower()
                data = rsp.read()
                if 'gzip' in content_encoding:
                    try:
                        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                            data = f.read()
                    except Exception as e:
                        logger.error(f"Gzip 解压错误: {str(e)}")
                        return None
                return json.loads(data.decode('utf-8'))     
        except Exception as e:
            logger.error(f"获取 {url} 失败: {str(e)}")
            return None
    
    def select_cdn(self):
        if self.launcher_info is None: return None
        cdnlist = self.launcher_info['default'].get('cdnList', None)
        if not cdnlist: return None
        
        available_nodes = [node for node in cdnlist if node['K1'] == 1 and node['K2'] == 1]
        if not available_nodes:
            return None
        
        max_priority = max(node['P'] for node in available_nodes)
        
        for node in available_nodes:
            if node['P'] == max_priority:
                logger.info(f"选择 CDN: {node['url']}")
                return node['url']
    
    def get_gamefile_index(self):
        if self.launcher_info is None: return None
        indexfile_uri = self.launcher_info['default']['config']['indexFile']
        logger.info("正在获取文件清单 (indexFile.json)...")
        indexfile = self.get_result(urljoin(self.cdn_node, indexfile_uri))
        return indexfile
        
    def download_file_with_resume(self, url, file_path: Path, overwrite=False, file_size_expected=None):
        directory = file_path.parent
        if not directory.exists():
            os.makedirs(directory)
        
        temp_file_path = file_path.with_suffix(file_path.suffix + '.temp')
        
        if file_path.exists():
            if not overwrite:
                return True
            else:
                os.remove(file_path)

        downloaded_bytes = 0
        if temp_file_path.exists():
            downloaded_bytes = os.path.getsize(temp_file_path)
            
        headers = {'User-Agent': 'Mozilla/5.0'}
        if downloaded_bytes > 0:
            headers['Range'] = f'bytes={downloaded_bytes}-'
            
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as rsp:
                total_size = file_size_expected
                if total_size is None:
                    total_size = int(rsp.headers.get('Content-Length', 0))
                
                if rsp.status == 206:
                    total_size = downloaded_bytes + int(rsp.headers.get('Content-Length'))
                elif rsp.status == 200:
                    if downloaded_bytes > 0:
                        logger.warning("服务器不支持断点续传, 重新下载.")
                    downloaded_bytes = 0
                else:
                    logger.error(f"下载失败 (HTTP: {rsp.status}): {file_path.name}")
                    return False
                
                mode = "ab" if downloaded_bytes > 0 else "wb"
                
                with TqdmUpTo(
                    unit='B', unit_scale=True, miniters=1,
                    desc=f"  {file_path.name[:30]:<30}", total=total_size, initial=downloaded_bytes,
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]'
                ) as pbar:
                    with open(temp_file_path, mode) as file:
                        while True:
                            chunk = rsp.read(1024 * 1024) # 1MB chunk
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
                with open(self.md5_cache_path, 'r', encoding='utf-8') as f:
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
            with open(self.md5_cache_path, 'w', encoding='utf-8') as f:
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
                if cached_data['mtime'] == mtime:
                    logger.debug(f"命中缓存: {relative_path_str}")
                    return cached_data['md5']
            
            logger.info(f"(计算中): {relative_path_str}")
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096 * 1024), b""): # 4MB chunk
                    md5_hash.update(chunk)
            
            new_md5 = md5_hash.hexdigest()
            self.md5_cache[relative_path_str] = {'mtime': mtime, 'md5': new_md5}
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
            "appId": config["appId"] # 关键: 写入正确的 appId
        }
        file_path = self.game_folder_path / "launcherDownloadConfig.json"
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(temp, file, ensure_ascii=False, indent=4)
            logger.info(f"已更新 launcherDownloadConfig.json (Version: {version}, AppId: {config['appId']})")
        except Exception as e:
            logger.error(f"写入 launcherDownloadConfig.json 失败: {e}")

    # --- CLI 命令对应的功能 ---
    def download_game(self):
        """(download) 下载所有游戏文件"""
        logger.info(f"开始为 {self.server_type} 服下载完整游戏...")
        resource_list = list(self.gamefile_index['resource'])
        total = len(resource_list)
        
        for i, file in enumerate(resource_list):
            logger.info(f"--- 进度 {i+1}/{total} ---")
            download_url = urljoin(self.cdn_node, self.resources_base_path + "/" + file['dest'])
            download_url = quote(download_url, safe=':/')
            file_path = self.game_folder_path.joinpath(Path(file['dest']))
            
            current_md5 = self.get_file_md5(file_path)
            if current_md5 == file['md5']:
                logger.info(f"文件已存在且 MD5 匹配 (跳过): {file['dest']}")
                continue
            
            self.download_file_with_resume(
                url=download_url,
                file_path=file_path,
                overwrite=True, 
                file_size_expected=int(file['size'])
            )
        
        logger.info("完整下载任务完成。")
        self.update_localVersion(self.server_type, self.current_version)
        self.save_md5_cache()

    def sync_gamefile(self):
        """(sync) 校验、同步和清理文件 (慢速但100%准确)"""
        logger.info(f"开始校验 {self.server_type} 服的文件...")
        resource_list = list(self.gamefile_index['resource'])
        
        # 1. 构建所有预期文件的 Set
        expected_files_map = {item['dest']: item for item in resource_list}
        expected_relative_paths = set(expected_files_map.keys())

        # 2. 智能重命名 (清理/烘焙)
        diff_check_dirs = [
            self.game_folder_path / "Client" / "Content" / "Paks",
            self.game_folder_path / "Client" / "Binaries" / "Win64"
        ]

        logger.info("正在检查差异文件...")
        files_to_check = []
        for d in diff_check_dirs:
            if d.exists():
                files_to_check.extend(d.glob('*.pak'))
                files_to_check.extend(d.glob('*.dll'))
                files_to_check.extend(d.glob('*.pak.bak'))
                files_to_check.extend(d.glob('*.dll.bak'))

        for file_path in files_to_check:
            try:
                relative_path_str = str(file_path.relative_to(self.game_folder_path)).replace("\\", "/")
                
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
            file_path = self.game_folder_path.joinpath(Path(file['dest']))
            
            current_md5 = self.get_file_md5(file_path)
            expected_md5 = file['md5']

            if current_md5 == expected_md5:
                continue
            
            if file_path.exists():
                logger.warning(f"({i+1}/{total}) MD5 不匹配: {file['dest']}")
            else:
                 logger.info(f"({i+1}/{total}) 文件缺失: {file['dest']}")
            
            download_url = urljoin(self.cdn_node, self.resources_base_path + "/" + file['dest'])
            download_url = quote(download_url, safe=':/')
            self.download_file_with_resume(
                url=download_url, 
                file_path=file_path, 
                overwrite=True,
                file_size_expected=int(file['size'])
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
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        appId = data.get('appId')
        version = data.get('version')
        server = APPID_TO_SERVER.get(appId, "unknown")
        return server, version
    except Exception as e:
        logger.error(f"读取 {config_path} 失败: {e}")
        return None, None

def handle_status(args):
    logger.info("--- 状态检查 ---")
    server, version = get_current_server(args.path)
    if server:
        print(f"  游戏目录: {args.path.resolve()}")
        print(f"  当前服务器: {server}")
        print(f"  当前版本: {version}")
    else:
        print(f"  未在 {args.path} 中找到有效的游戏配置。")

def handle_sync(args):
    logger.info("--- 同步当前服务器 (慢速/修复) ---")
    server, _ = get_current_server(args.path)
    if not server or server == "unknown":
        logger.error("无法确定当前服务器类型。请先使用 'download' 或 'checkout'。")
        return
        
    logger.info(f"检测到当前服务器为: {server}。开始同步...")
    launcher = WDLancher(args.path, server)
    launcher.sync_gamefile()

def handle_checkout(args):
    """(checkout) 快速切换逻辑"""
    logger.info(f"--- 快速切换服务器 ---")
    target_server = args.server
    game_path = args.path
    
    if target_server not in SERVER_CONFIGS:
        logger.error(f"无效的服务器: {target_server}. 可选: {list(SERVER_CONFIGS.keys())}")
        return
    
    current_server, current_version = get_current_server(game_path)
    if current_server == target_server:
        logger.warning(f"当前已经是 {target_server} 服。")
        if args.force_sync:
            logger.info("强制执行 'sync'...")
            handle_sync(args)
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
    temp_launcher = WDLancher(game_path, target_server) 
    temp_launcher.update_localVersion(target_server, version_to_write)
    
    if missing_files:
        logger.warning("--- 切换完成，但检测到文件缺失 ---")
        logger.warning(f"您的游戏目录不是 '全家桶'，缺少 {target_server} 服的差异文件。")
    else:
        logger.info("--- 切换完成 ---")

    # 确保 --force-sync 总是被检查
    if args.force_sync:
        logger.info("强制执行 'sync'...")
        handle_sync(args)
    elif missing_files:
        logger.warning(f"请立即运行 'sync' 命令来下载缺失文件:")
        print(f"\n{sys.argv[0]} -p \"{game_path}\" sync\n") # 使用 sys.argv[0] (别名)

def handle_download(args):
    logger.info("--- 下载完整游戏 (慢速) ---")
    target_server = args.server
    if target_server not in SERVER_CONFIGS:
        logger.error(f"无效的服务器: {target_server}. 可选: {list(SERVER_CONFIGS.keys())}")
        return
    
    logger.warning(f"将要下载 {target_server} 服的完整客户端到 {args.path}")
    
    launcher = WDLancher(args.path, target_server)
    launcher.download_game()
    logger.info("下载完成。现在开始强制校验一遍...")
    launcher.sync_gamefile() 
    logger.info(f"完整客户端 ( {target_server} ) 下载并校验完成。")

def handle_clear_path(args, app_config):
    if "default_path" in app_config:
        del app_config["default_path"]
        save_app_config(app_config)
        logger.info(f"已清除保存的游戏路径。")
    else:
        logger.info("没有保存的游戏路径。")

# --- 主函数和 Argparse ---

def main():
    app_config = load_app_config()
    default_path = app_config.get("default_path")

    parser = argparse.ArgumentParser(
        description="鸣潮 (Wuthering Waves) 命令行下载/切换管理器",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    path_help = "游戏《Wuthering Waves Game》目录路径。"
    if default_path:
        path_help += f"\n(默认: {default_path})"
    else:
        path_help += "\n(使用 -p 指定一次后将自动保存)"

    parser.add_argument(
        "-p", "--path",
        type=Path,
        required=False,
        default=default_path,
        help=path_help
    )
    # ---------------------------------------------
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="操作命令")

    # 1. status
    parser_status = subparsers.add_parser(
        "status",
        help="检查当前游戏目录的服务器类型和版本"
    )
    parser_status.set_defaults(func=handle_status)

    # 2. sync
    parser_sync = subparsers.add_parser(
        "sync",
        help="[慢速] 校验当前服务器的文件，下载缺失/损坏文件，并烘焙差异文件 (修复/更新)"
    )
    parser_sync.set_defaults(func=handle_sync)

    # 3. checkout
    parser_checkout = subparsers.add_parser(
        "checkout",
        help="[快速] 立即切换到另一个服务器 (仅重命名差异文件)"
    )
    parser_checkout.add_argument(
        "server",
        choices=SERVER_CONFIGS.keys(),
        help="要切换到的目标服务器"
    )
    parser_checkout.add_argument(
        "--force-sync",
        action="store_true",
        help="[可选] 在快速切换完成后，立即强制执行一次 'sync' 校验"
    )
    parser_checkout.set_defaults(func=handle_checkout)
    
    # 4. download
    parser_download = subparsers.add_parser(
        "download",
        help="[慢速] 下载一个全新的、完整的服务器客户端 (会执行 sync)"
    )
    parser_download.add_argument(
        "server",
        choices=SERVER_CONFIGS.keys(),
        help="要下载的目标服务器"
    )
    parser_download.set_defaults(func=handle_download)
    
    parser_clear = subparsers.add_parser(
        "clear-path",
        help="清除已保存的默认游戏路径"
    )
    parser_clear.set_defaults(func=handle_clear_path)
    # --------------------------

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    if args.command == 'clear-path':
        args.func(args, app_config)
        sys.exit(0)
    # -------------------------------

    if not args.path:
        # 这个错误只会在用户从未设置过 -p 并且 default_path 为 None 时触发
        logger.error("错误: 缺少游戏路径。")
        logger.error(f"请至少使用 -p /path/to/game 运行一次以设置默认路径。")
        parser.print_help()
        sys.exit(1)
    
    # 确保 args.path 是 Path 对象
    args.path = Path(args.path)

    # 自动保存新路径
    if str(args.path.resolve()) != default_path:
        logger.info(f"设置新的默认游戏路径为: {args.path.resolve()}")
        app_config["default_path"] = str(args.path.resolve())
        save_app_config(app_config)
    # -------------------------------

    args.func(args)

if __name__ == "__main__":
    import certifi
    os.environ["SSL_CERT_FILE"] = certifi.where()
    main()
