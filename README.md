# 鸣潮 (Wuthering Waves) CLI Manager

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Manager](https://img.shields.io/badge/Tool-uv-purple.svg)](https://github.com/astral-sh/uv)

专为 Linux 用户打造的《鸣潮》客户端命令行管理工具。

结合了 **完整的下载/校验功能** 与 **秒级服务器切换** 技术。一旦完成“烘焙”，即可在国服 (CN)、B服 (Bilibili) 和国际服 (Global) 之间瞬时切换，无需重新下载庞大的游戏文件。

## ✨ 核心功能

* **🚀 秒级切换 (`checkout`)**：利用差异文件重命名技术，在不同服务器间瞬间切换。
* **🛠️ 智能修复 (`sync`)**：校验全量文件 MD5，自动修复损坏文件，下载缺失资源。
* **📦 完整下载 (`download`)**：从零开始下载任一服务器的纯净客户端。
* **💾 自动记忆**：自动记录游戏路径，一次设置，永久生效。
* **⚡️ 现代化 CLI**：基于 `Typer` 构建，支持自动补全和帮助信息。

## 🔧 安装指南

本工具推荐使用 [uv](https://github.com/astral-sh/uv) 进行安装和管理。

### 1. 安装 uv (如果尚未安装)

```bash
curl -LsSf [https://astral.sh/uv/install.sh](https://astral.sh/uv/install.sh) | sh
````

### 2\. 安装本工具

在源码目录下执行：

```bash
uv tool install .
```

安装完成后，你就可以在终端的任意位置直接使用 **`ww`** 命令了！

> **升级/重新安装**：
> 如果修改了代码，可以使用 `uv tool install . --force` 重新安装。

## 📖 使用说明

### 首次运行

第一次运行时，你需要指定游戏路径（只需指定一次，后续会自动记忆）：

```bash
# 创建安装目录(如果你还没有创建游戏目录)
mkdir -p "$HOME/Games/WutheringWaves" 
# 初始化路径
ww -p "$HOME/Games/WutheringWaves" status
```
### 常用命令

#### 1\. 查看状态 (`status`)

检查当前游戏目录属于哪个服务器，以及版本号。

```bash
ww status
```

#### 2\. 快速切换服务器 (`checkout`)

这是最常用的功能。在已下载好差异文件的情况下，**秒级**切换服务器。

```bash
# 切换到 Bilibili 服
ww checkout bilibili

# 切换到 国服
ww checkout cn

# 切换到 国际服
ww checkout global
```

> **注意**：如果切换后提示“文件缺失”，请运行 `ww sync` 进行下载修复。
>
> 也可以一步到位，运行 `ww checkout cn --force-sync` 同时完成切换和同步。 

#### 3\. 同步与修复 (`sync`)

**每次游戏版本更新后**，或者切换服务器后发现文件缺失时使用。它会联网校验所有文件并下载更新。

```bash
ww sync
```

#### 4\. 下载完整客户端 (`download`)

如果你还没有游戏，可以使用此命令从零开始下载。

```bash
# 下载完整的国服客户端到当前目录（或配置的默认目录）
ww download cn
```

## 💡 最佳实践：如何打造“全家桶”

要实现完美的秒级切换，你需要将所有服务器的“差异文件”都下载到同一个目录中。

1. **下载基础客户端**：
    如果你还没有游戏，先下载一个完整的（例如国服）：

    ```bash
    ww --path "/path/to/Game" download cn
    ```

2. **“烘焙”其他服务器**：
    现在切换到 B 服，并强制执行同步来下载 B 服独有的文件（如 `bilibili_sdk.dll`）：

    ```bash
    ww checkout bilibili --force-sync
    ```

3. **享受切换**：
    现在你已经拥有了“全家桶”。

      * 想玩官服？ `ww checkout cn`
      * 想玩B服？ `ww checkout bilibili`

## 🎮 启动游戏 (Linux)

本工具仅负责文件管理。启动游戏推荐使用 Steam + Proton。

如果你熟悉 Linux，你可以参考项目中的 `run_ww.sh` 脚本并添加 .desktop 文件绕过 Steam 启动，或者按照以下步骤通过 Steam 启动：

1. **Steam 设置**：

      * 添加“非 Steam 游戏”，指向 `/Client/Binaries/Win64/Client-Win64-Shipping.exe`。
      * 在兼容性中强制使用 `GE-Proton` (参考项目` LutheringLaves` 下载最新 GE-Proton)。

2. **启动参数**：
    在 Steam 启动选项中添加：

    ```bash
    steamdeck=1
    ```

## 卸载

如果你不再需要本工具：

```bash
uv tool uninstall ww-manager
```

## 致谢

灵感来源于以下优秀项目：

* [WutheringWavesTool](https://github.com/leck995/WutheringWavesTool)
* [LutheringLaves](https://www.google.com/search?q=https://github.com/last-live/LutheringLaves)
* [Wuthering-Waves-Official-Bilibili](https://www.google.com/search?q=https://github.com/Hurry1027/Wuthering-Waves-Official-Bilibili)

<!-- end list -->

### 接下来该做什么？

如果有任何报错或者建议，随时通过 **issue** 告诉我！

