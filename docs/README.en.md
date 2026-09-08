<div align="center"><h1>WutheringWaves CLI Manager</h1><h3>Command-line manager for Wuthering Waves</h3><div align="center">
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python 3.9+"></a>&nbsp;<a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/badge/Tool-uv-purple.svg" alt="uv"></a>&nbsp;<img src="https://img.shields.io/badge/Version-2.2.5-brightgreen.svg" alt="version 2.2.5">
</div>
</div>

<div align="center" style="width: 80%;">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 80%;">
        <img src="https://cdn.jsdelivr.net/gh/timetetng/Pic-Bed@main/ww-example1.png" alt="badge" style="width: 40%; height: auto;">
        <img src="https://cdn.jsdelivr.net/gh/timetetng/Pic-Bed@main/ww-example2.png" alt="CLI preview" style="width: 40%; height: auto;">
    </div>
</div>

> 🌐 **中文**: [README.md](../README.md)

A command-line management tool for the *Wuthering Waves* client, built for **Linux** users.
It combines **complete download/verification capabilities** with **instant server switching**. Once "baked", you can switch between the CN (official) server and the Bilibili server in seconds, without re-downloading the huge game files.

> **Instant switching is not supported for the Global server due to package differences.**
>
> The latest release has been tested and is also compatible with Windows 11.

## ✨ Key Features

* **🚀 Instant switching (`checkout`)**: MD5-based fast verification — only replaced files are swapped, switching between servers in seconds.
* **🛠️ Smart repair (`sync`)**: Verifies MD5s of all files, automatically repairs corrupted files and downloads missing resources.
* **📦 Full download (`download`)**: Downloads a pristine client for any server from scratch.
* **🔥 Pre-download / incremental update (`predownload`)**: Fetches incremental packages during the pre-download window and merges patches after maintenance; once a new version goes live you can also update incrementally. Based on patch binaries extracted from the official launcher (see releases) — feedback and bug reports welcome. `incremental` is an alias.
* **💾 Remembers your setup**: The game path is remembered automatically — set it once, and it works forever.
* **⚡️ Modern CLI**: Built with `Typer`, with shell completion and help support.
* **👯 Parallel downloads**: Multi-threaded downloads to avoid CDN throttling, with resume support.

## 🔧 Installation

Multiple install methods are supported; using [**uv**](https://github.com/astral-sh/uv) is recommended.

### AUR

```bash
yay -S ww-manager
```

---

### 🚀 With uv

#### 1. Install uv

* **Linux / macOS:**
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```
* **Windows:**
    ```pwsh
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

> **Tip**: After installation, **restart your terminal** so the environment variables take effect.

#### 2. Install the tool

* Option 1: install from PyPI (recommended)
```bash
uv tool install ww-manager
```

* Option 2: build from source
```bash
git clone https://github.com/timetetng/wutheringwaves-cli-manager.git
cd wutheringwaves-cli-manager

# Install inside the source directory
uv tool install .
```

#### 3. Update the tool

```bash
ww update
```

#### 4. Uninstall the tool

```bash
uv tool uninstall ww-manager
```

## 📖 Usage

On first run you need to specify the game path (only once; it will be remembered afterwards):

```bash
# Create the install directory (if you don't have a game directory yet)
mkdir -p "$HOME/Games/WutheringWaves"
# Initialize the path
ww -p "$HOME/Games/WutheringWaves" status
```

> The `-p` / `--path` option specifies the install path.

### Common commands

#### 1\. Check status (`status`)

Checks which server the current game directory belongs to, and the version.

```bash
ww status
```

#### 2\. Switch servers (`checkout`)

**Instant** server switching (CN / Bilibili only).

Switching between the CN and Bilibili servers uses a **differential-file cache**: the first switch downloads the diff files and stores them in `wwm_server_diff_cache/` inside the game directory; subsequent switches restore from the local cache first — no re-download needed, falling back to CDN download on failure. The cache is reset automatically on major version updates (e.g. 3.4 → 3.5).

```bash
# Switch to the Bilibili server
ww checkout bilibili
# Switch to the CN (official) server
ww checkout cn
# Switch to the Global server (package differs too much: full download needed, no diff cache)
ww checkout global
# Force a full verification sync (fallback)
ww checkout cn --force-sync
```

#### 3\. Sync & repair (`sync`)

Use this when files are missing after switching servers or an interrupted download. It verifies all files online and downloads updates. For version updates use `ww predownload` to pre-download / incrementally update (`ww predownload --apply` applies).

```bash
ww sync
```

> When a sync completes, stale leftover files from previous updates (e.g. old paks) are cleaned automatically so old files can't shadow new ones and break startup; user files and runtime resources are left untouched.

#### 4\. Download the full client (`download`)

Use this command to download from scratch.

```bash
# Downloads the full CN client into the configured directory
ww download cn
```

#### 5\. Pre-download / incremental update (`predownload`, alias `incremental`)

During the pre-download window of a new version, use this command to fetch the incremental package early, then apply the merged patch after maintenance. Once the new version goes live the same command performs a direct incremental update (no full `sync` needed). `incremental` and `predownload` are interchangeable.

```bash
# Download the incremental package (early during pre-download; or directly after the new version goes live)
ww predownload

# Apply the incremental update (merge patch after maintenance)
ww predownload --apply

# Same usage with the alias
ww incremental
ww incremental --apply
```

> [!CAUTION]
> 1. **You can start downloading the incremental package as soon as pre-download opens** (the channel turns into a direct incremental update after the new version goes live);
> 2. **If the apply is interrupted, retry `ww predownload --apply`**;
> 3. **If files are still missing after applying, run `ww sync`**;
> 4. **Make sure the install directory has enough free space (twice the size is needed to copy source files for patch merging)**

#### 6\. Get the gacha log link (`log`)

Fetch the gacha record link in one go, for importing into miniapps or Wuthering Waves bots.

```bash
# Open 唤取-唤取记录 (gacha records) in game first to refresh the log file
ww log
```

> `-o` / `--open`: fetch the link and open it directly.

#### 7\. Update the tool itself (`update`)
Checks the install method automatically and tries to update.

```bash
ww update
```

## 🎮 Launching the game (Linux)

This tool only manages files. For launching the game, Steam + Proton is recommended.

If you're comfortable with Linux, you can use the `run_ww.sh` script in this repo together with a .desktop file to bypass Steam, or launch via Steam as follows:

1. **Steam settings**:

      * Add a "Non-Steam game" pointing to `安装目录/Client/Binaries/Win64/Client-Win64-Shipping.exe` (replace 安装目录 with your install directory).
      * Force `GE-Proton` or `dwproton` in compatibility settings (switch Proton if ACE warnings persist).

2. **Launch options**:
     Add to Steam launch options:

    ```bash
    steamdeck=1
    ```

## 🛠️ FAQ

> [!TIP]
> Linux environments vary a lot; the solutions below come from the community and are for reference only.

---

### Q1: Kicked offline by the ACE anti-cheat warning — how to fix?
* **Recommended**: use `dwproton` or set the environment variable `steamdeck=1`.
* **Effect**: noticeably reduces detection frequency, but cannot eliminate it completely.
* **Experimental**: the community mentions swapping the ACE component from Strinova (卡拉彼丘); this method is **unverified** — research at your own risk.

---

### Q2: Kicked offline after ~10 minutes, need to re-login?
This is usually an environment-identification problem at startup. If switching launch methods doesn't help, **CN-server users** can try the solution from Bilibili user `@神麤詭末`:

1.  **Locate the file**: `安装目录/Client/Binaries/Win64/ThirdParty/KrPcSdk_Mainland/KRSDKRes/KRSDKConfig.json`
2.  **Modify the field**: change `KR_ChannelId` from `19` (CN official) to `205` (Steam).
3.  **At startup**: if a "network error" pops up, just click **Retry**.

> [!CAUTION]
> 1. **Back up the original file before editing** — otherwise you may not be able to fix it!
> 2. This method **does not work on the Bilibili server**.

---

### Q3: Wrong story text or missing assets?
1.  **Sync first**: run `ww sync`.
2.  **Environment check**: if problems persist after syncing, they are usually not in the game files — try a different **launch method**, **desktop environment (DE)**, or **Wine/Proton version**.

---

### Q4: Login box can't focus/accept input?
Using Arch Linux + Steam-launched Wuthering Waves as an example:

1. Install `protontricks`: `sudo pacman -S protontricks`;
2. Run `protontricks --gui`, find Wuthering Waves in the list;
3. Choose `Select the default wineprefix -> Run winecfg`;
4. In the winecfg window, go to the **Graphics** tab and tick **Emulate a virtual desktop**, then set a resolution;
5. Apply and restart the game — input/login should work now;
6. After logging in, run `protontricks` again and untick the virtual desktop.

---

### Q5: Any other way to download/update Wuthering Waves?
Of course 👌 — for users who want to run the **official launcher** on Linux:

[Running the official Wuthering Waves launcher on Linux](./wuwa-launcher.md)

> [!NOTE]
> The original author's blog domain is expiring, so [`wuwa-launcher.md`](./wuwa-launcher.md) has been archived as a mirror in this docs directory. Original URL:
> https://site.moyingji.one/linux/gaming/workarounds/wuwa-launcher

---

### 📢 Feedback
Please open an **Issue** for any problem; **PRs** are welcome.

## Acknowledgements

Thanks to these great projects:

* [WutheringWavesTool](https://github.com/leck995/WutheringWavesTool)
* [LutheringLaves](https://github.com/last-live/LutheringLaves)
* [Wuthering-Waves-Official-Bilibili](https://github.com/Hurry1027/Wuthering-Waves-Official-Bilibili)
* [GE-Proton](https://github.com/GloriousEggroll/proton-ge-custom/releases/): download the latest `GE-Proton` and extract it into `~/.local/share/Steam/steamapps/common/`, then start Steam — you'll find the downloaded `GE-Proton` under **Properties → Compatibility**.
* [dwproton](https://dawn.wine/dawn-winery/dwproton/releases): installed the same way as above

<!-- end list -->
