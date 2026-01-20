#!/bin/bash
# Linux 终末地食用指南
# 1. 官网下载启动器 HypergryphLauncher_1.0.0_1_1_endfield.exe
# 2. 下载 [dwproton](https://dawn.wine/dawn-winery/dwproton/releases) 并解压到 ~/.local/share/Steam/compatibilitytools.d (同本项目的GE-Proton安装方式，Steam 能识别到即可)
# 3. 使用 Steam 添加非 Steam 游戏打开启动器，属性开启强制兼容性，并勾选 dwproton, 启动参数 steamdeck=1, 启动游戏
# 4. 初次使用需选择安装路径，全部默认即可，将会安装在形如 .local/share/Steam/steamapps/compatdata/4046059116(随机数字)/pfx/drive_c/ 这个容器的虚拟C盘中
# 5. 可以选择在初次启动下载全部游戏资源，然后将对应路径填写到下面的脚本中
# 6. 创建 ~/.local/share/applications/Endfield.desktop 并以本脚本为启动命令，可以自行配置图标等信息。此后可以直接从应用菜单启动，无需 Steam


# Proton 路径(实测终末地需要dwproton)
PROTON_BIN="$HOME/.local/share/Steam/compatibilitytools.d/dwproton-10.0-14/proton"

# 游戏路径
GAME_EXE="/home/xingjian/.local/share/Steam/steamapps/compatdata/4046059116/pfx/drive_c/Program Files/Hypergryph Launcher/games/Endfield Game/Endfield.exe"

# steam 游戏目录路径
export STEAM_COMPAT_DATA_PATH="$HOME/.local/share/Steam/steamapps/compatdata/4046059116"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.local/share/Steam"

# 环境变量
export STEAMDESK=1
# 用于帧率显示(sudo pacman -S mangohud 安装)
#export MANGOHUD=1

# 定义 Steam 内部自带的 Runtime 脚本路径
STEAM_RUNTIME_SCRIPT="$HOME/.local/share/Steam/ubuntu12_32/steam-runtime/run.sh"

echo "正在启动终末地 (使用 Steam Internal Runtime)..."

# 检查脚本是否存在，存在则使用，不存在则裸奔
if [ -f "$STEAM_RUNTIME_SCRIPT" ]; then
  "$STEAM_RUNTIME_SCRIPT" gamemoderun "$PROTON_BIN" run "$GAME_EXE"
else
  echo "警告：未找到 Steam Runtime，过场动画可能黑屏"
  gamemoderun "$PROTON_BIN" run "$GAME_EXE"
fi
