# 🛡️ Minecraft SS / Anti-Cheat Tool (Windows)

A Windows-only **Minecraft screenshare support tool** designed to help detect suspicious activity such as hacked clients, autoclickers, illegal mods, and tampered logs.  
It scans memory, disk, logs, deleted executables, and more to assist with cheat detection.

## ✨ Features

- **Memory Scan (javaw.exe)**
  - Detects hacked-client signatures
  - Flags generic cheat keywords
  - Extracts minecraft usernames

- **Disk Scan**
  - Scans all common Minecraft launcher directories (Mojang, Microsoft Store, MultiMC, PrismLauncher, Technic, ATLauncher, Lunar Client, Badlion, CurseForge, GDLauncher, etc.)
  - Scans for suspicious or illegal mods by **keywords** or **known bad hashes**

- **Logs Scan**
  - Parses `latest.log` and archived logs
  - Detects suspicious markers (`baritone`, `liquidbounce`, `wurst`, `meteor`, etc.)
  - Extracts recent servers and IP addresses to logs

- **Deleted EXE/JAR Detection**
  - Prefetch analysis
  - PCA / Explorer memory (credits to AstroSS, https://github.com/Jammy108/AstroSS/tree/master)
  - Recycle Bin scanning
  - Supports `.exe` **and** `.jar` files

- **JNativeHook DLL Scan**
  - Detects common injection DLLs dropped into `Temp`

- **Environment Awareness**
  - Logs running screen recording / overlay software (OBS, Bandicam, ShadowPlay, etc.)
  - Prevents bypass of screenshare through use of overlay software.

- **Classification**
  - Produces a final verdict:
    - `CLEAN`
    - `SUSPICIOUS`
    - `DIRTY / HACKING`
  - Includes reasons (e.g. "Illegal mods found", "Suspicious logs", "Injected signatures in memory")
