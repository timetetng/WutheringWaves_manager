# 鸣潮 (Wuthering Waves) 命令行管理器

这是一个为 Linux 用户设计的 Python 命令行 CLI 工具，用于管理《鸣潮》客户端，灵感来源于 `LutheringLaves` 和 `wuthering-waves-official-bilibili` 项目。

它结合了两种工具的优点：

  * **完整的下载/校验功能**：可以从零开始下载、修复或更新任一服务器的客户端。
  * **秒级的快速切换**：一旦“烘焙”完成（见推荐流程），即可在官服、B服、国际服之间瞬时切换。

## ✨ 功能

  * **服务器支持**：支持国服 (cn)、Bilibili (bilibili) 和国际服 (global)。
  * **`status`**：检查当前游戏目录的服务器类型和版本。
  * **`download`**：[慢速] 从零开始下载一个完整的、纯净的服务器客户端。
  * **`sync`**：[慢速] 校验当前服务器的所有文件，修复/下载缺失或损坏的文件，并自动处理差异文件（重命名备份）。**用于游戏版本更新或修复**。
  * **`checkout`**：[快速] 在已“烘焙”的客户端之间**秒级切换**。它只重命名差异文件，不进行网络或MD5校验。
  * **MD5 缓存**：`sync` 和 `download` 命令会自动缓存已校验文件的 MD5 值，极大提升后续校验速度。
  * **路径记忆**：首次使用 `-p path` 后，会自动记忆游戏目录，下次使用更方便。

## 🔧 依赖

  * Python 3.8+
  * Python 依赖包：`tqdm` (用于进度条)

你可以使用 `pip` 或 `uv` (推荐) 来安装依赖：

```bash
uv pip install tqdm certifi
```

*(脚本已内置 `certifi` 支持以解决 SSL 证书问题)*

## 🚀 命令详解

所有命令都依赖一个**全局参数**：

  * `-p, --path <游戏目录>`：**必须**指定。指向《鸣潮》的游戏根目录，即 `Wuthering Waves.exe` 所在的 `Wuthering Waves Game` 文件夹。
  * `-h, --help`: 查看帮助命令

-----

### 1\. status

检查当前游戏目录配置的服务器和版本。

```bash
uv run ww_manager.py -p "/path/to/Wuthering Waves Game" status
```

**输出示例:**

```
2025-11-16 14:01:25,406 [INFO] --- 状态检查 ---
  游戏目录: /path/to/Wuthering Waves Game
  当前服务器: bilibili
  当前版本: 2.7.0
```

-----

### 2\. download `<server>`

[慢速] 下载一个全新的、完整的客户端。

  * `<server>`: `cn`, `bilibili`, 或 `global`。
  * 它会下载目标服务器的**所有**文件。
  * 下载完成后，会自动执行一次 `sync` 来确保文件100%正确。

<!-- end list -->

```bash
# 下载一个全新的B服客户端到指定目录
uv run ww_manager.py -p "/path/to/New Wuthering Waves Game" download bilibili
```

-----

### 3\. sync

[慢速] 同步、修复和更新。

  * 这是工具的核心功能。
  * 它会连接到当前配置的服务器API，获取完整的文件清单。
  * 使用MD5缓存（如果存在）快速校验所有本地文件。
  * 自动下载缺失、损坏或版本过时的文件。
  * 自动将**不属于**当前服务器清单的已知差异文件（如 `pakchunk1-Kuro...pak`）重命名为 `.bak`。

**这是你每次游戏大版本更新后都应该执行的命令。**

```bash
# 修复/更新当前目录（假设是B服）
uv run ww_manager.py -p "/path/to/Wuthering Waves Game" sync
```

-----

### 4\. checkout `<server>`

[快速] 瞬时切换服务器。

  * 这是工具的核心快速功能。
  * 它**不联网**，**不校验MD5**。
  * 它只执行文件重命名：
    1.  禁用当前服的差异文件 (例如 `...Kuro.pak` -\> `...Kuro.pak.bak`)。
    2.  启用目标服的差异文件 (例如 `...Bilibili.pak.bak` -\> `...Bilibili.pak`)。
    3.  重写 `launcherDownloadConfig.json` 指向新服务器。

**重要**：此命令依赖一个“全家桶”式的游戏目录（即所有服务器的差异文件都已存在）。如果文件不存在，它会切换失败并提示你运行 `sync`。

```bash
# 假设当前是官服，秒切到B服
uv run ww_manager.py -p "/path/to/Wuthering Waves Game" checkout bilibili
```

**可选参数：`--force-sync`**

这是一个便利参数，它会在**快速切换完成后，立即强制执行一次 `sync`**。这对于首次“烘焙”目录至关重要。

```bash
# 首次从官服切换到B服时，用于下载B服的差异文件
uv run ww_manager.py -p "/path/to/Wuthering Waves Game" checkout bilibili --force-sync
```

## 💡 推荐工作流程 (如何"烘焙"全家桶)

要享受秒级切换，你需要一个包含所有服务器差异文件的“全家桶”目录。

### 步骤 1: 首次安装 (以官服为例)

在一个（建议的）空目录中下载完整的官服客户端。

```bash
uv run ww_manager.py -p "/home/user/Games/WW_Game" download cn
```

*(等待下载和`sync`完成。此时你有了官服。)*

或者，你已经有一个完整的游戏包体了,那只需要将路径定位到`Wuthering Waves.exe` 所在目录，然后执行步骤二即可。

### 步骤 2: 烘焙B服

使用 `checkout --force-sync` 来添加B服的差异文件。

```bash
uv run ww_manager.py -p "/home/user/Games/WW_Game" checkout bilibili --force-sync
```

  * `checkout` 会秒级切换配置（并报告B服文件缺失）。
  * `--force-sync` 会立即运行 `sync`。
  * `sync` 会检测到B服，然后下载缺失的 `bilibili_sdk.dll` 和 `pakchunk1-Bilibili...pak`，并自动将官服的 `kuro_login.dll` 和 `pakchunk1-Kuro...pak` 备份为 `.bak`。

*(烘焙完成！你的目录现在是B服，并包含了官服的备份文件。)*

### 步骤 3: 享受秒级切换

现在你可以不带 `--force-sync` 来回切换了。

```bash
# 切换回官服 (秒级)
uv run ww_manager.py -p "/home/user/Games/WW_Game" checkout cn

# 切换回B服 (秒级)
uv run ww_manager.py -p "/home/user/Games/WW_Game" checkout bilibili
```

### 步骤 4: 游戏版本更新 (例如 2.8.0)

游戏大版本更新后，你需要为**每个**服务器都 `sync` 一次。

```bash
# 1. 确保你在官服
uv run ww_manager.py -p "/home/user/Games/WW_Game" checkout cn

# 2. 更新官服
uv run ww_manager.py -p "/home/user/Games/WW_Game" sync

# 3. 切换到B服
uv run ww_manager.py -p "/home/user/Games/WW_Game" checkout bilibili

# 4. 更新B服
uv run ww_manager.py -p "/home/user/Games/WW_Game" sync
```

*(这样可以确保两个服务器的差异文件都已更新到最新版本。)*

### 启动游戏

本脚本只提供游戏本体下载和快速切换功能，启动游戏需要参考 `LutheringLaves` 项目，下载最新的`Pronton` 兼容层，并在 `Steam` 中添加相关参数启动。

### 其他技巧

1. 成功运行后，脚本会自动记录 -p "your/path" 参数，下次无需带 -p 参数;
2. 可以将脚本启动命令加入 `~/.bashrc` 中，方便快速启动，下面是一个简单示例:
```bash
function ww() {
    /home/xingjian/Projects/Python/.venv/bin/python3.13 /home/xingjian/Projects/Python/wuwa_manager/wuwa_manager.py "$@"
}
```

### 致谢

感谢以下项目的灵感和工作！

#### 参考项目:

1. https://github.com/leck995/WutheringWavesTool.git
2. https://github.com/last-live/LutheringLaves.git
3. https://github.com/Hurry1027/Wuthering-Waves-Official-Bilibili.git
