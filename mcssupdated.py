#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aquoric's MC ssing tool
Python 3.8+

P.S, This tool is read-only and does not modify any system files.
Features are as folllows:
- Universal Compatibility: Windows 8+, x86/x64
- Memory scan of javaw.exe for hacked-client signatures & DPS/tooling strings & generic keywords; username extraction
- Disk scan of common launcher directories; keyword and hash vetting; .class awareness
- Logs scan: latest.log AND archived .gz
- Deleted EXE/JAR detection: Prefetch method, PCA/Explorer string scan, Recycle Bin hits against keywords
- JNativeHook DLL scan in %TEMP% (bad injected clients use ts method)
- Environment awareness: detects common recorders/overlays bc obs & other softwares have built-in overlay programs to bypass screenshare
- Classification: CLEAN / SUSPICIOUS / DIRTY + reasons
- Reporting: .txt and .json logs

Use with caution :)
"""

import os
import sys
import re
import io
import gzip
import glob
import json
import uuid
import math
import time
import ctypes
import platform
import hashlib
import traceback
import ctypes.wintypes as wintypes
from datetime import datetime
from collections import defaultdict, Counter

try:
    import psutil
except Exception:
    print("[!] psutil not found. Install with: pip install psutil")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    class _F: RED=YELLOW=GREEN=CYAN=MAGENTA=RESET=""
    class _S: RESET_ALL=""
    Fore=_F(); Style=_S()
    def colorama_init(*a, **k): pass

try:
    from tqdm import tqdm
except Exception:
    def tqdm(iterable=None, **kwargs):
        return iterable if iterable is not None else []
# -------------------------------------

colorama_init(autoreset=True)

TOOL_VERSION = "1.2.0"
SCAN_ID = uuid.uuid4().hex[:8]
START_TS = datetime.now()


# config/signatures

# keywords that flag in filenames, memory strings, .class names, etc.
ILLEGAL_KEYWORDS = [
    "xray","wurst","meteor","aristois","impact","liquidbounce","inertia",
    "sigma","kronos","killaura","reachmod","autoclick","aimassist","esp",
    "flux","huzuni","vape","rinject","incognito","bleach","bape","kryp",
    "ethylene","lemonade","pepe","phantom","verzide","mousetweaks","baritone",
    "injector"
]

# known memory signatures (injected clients)
JAVA_SIGNATURES = {
    "net/wurstclient/features/Mod": "Wurst Client",
    "META-INF/byCCBlueX/LiquidBounce/": "LiquidBounce",
    "assets/minecraft/flux/": "Flux Client",
    "impactclient": "Impact Client",
    "baritone": "Baritone Pathing",
    "inertia": "Inertia Client",
    "meteorclient": "Meteor Client",
    "killaura": "KillAura Module",
    "aimassist": "AimAssist Module",
    "reachmod": "Reach Module",
    "autoclicker": "AutoClicker Module",
    "xray.class": "XRay Module",
       ";9<C7D=CHCAL>@?DQI;MDSQRNQIMKEJ8": "Drip Cracked",
    "ZKM9.0.2": "Demon Injection Client",
    "| By JensDE": "Labymos v6 Client",
    "me/powns/cheatbreakerhud/settings/ModulesGui.class": "Grim Mod Client",
    "net.reach.Verzide": "Verzide Reach Mod",
    "tsgluke/betterstrafe": "TSGLuke Client",
    "io.conceal": "Conceal Injection Client",
    "me/tyler/util/CombatUtil.class": "Tyler Client",
    "trumpclientftw_": "Bape Mod Client",
    "<>ZRX44": "Trump Client",
    "xyz/Incide/gui": "Incide Client",
    "Cracked by rigole, enjoy your skid": "Onyc Client",
    "purgeclient/purgeclientD": "Purge Client",
    "me.veylkar.pepe": "Pepe Mod Client",
    "us.cuck.core.": "Cyanide Injection Client",
    "Injected into minecraft enjoy cheating you cuck": "Cyanide Injection Client",
    "pw/cinque/keystrokesmod/MouseButton$1.class": "KeystrokesMod Cheat",
    "keystr0kes": "Raven Mod Client",
    "pw/cinque/keystrokesmod/render/AwhhShitHeFuckedUp.classUT": "KeystrokesMod ASHFU Client",
    "Minecraft 1.7.10 | R:": "KeystrokesMod/BSP Reach",
    "knockback.setvalue": "AntiKB Mod",
    "Lemonade v1.8": "Lemonade Injection Client",
    "kyprak.agent": "Kyprak Injection Client",
    "xyz/gucciclient": "Gucci Mod Client",
    "me/massi/reach": "Massi Reach Mod",
    "BetterStrafe.class": "OmniSprint Client",
    "TcpNoDelayTweaker.classUT": "TcpNoDelay Cheat",
    "fitchi.agent": "Fitchi Injection Client",
    "net/minecraft/client/e/MASLJ": "MASLJ Client",
    "UniqueAntiLeak/": "Unique Client",
    "kappa_KappaClient_": "Kappa Client",
    "net/kohi/tcpnodelaymod/AUX": "TCPNoDelay Cheat",
    "Better Strafe Mod By Cheeky/Koupah": "Koupah Client",
    "IngameAccountSwitcher$1.class": "InGame Account Switcher",
    "stoud/merge": "Merge Client",
    "omikronclient.com": "Omikron Client",
    "d[>L6": "Xanax Client or Canalex Keystrokes Client",
    "tabbychat/injection": "TabbyChat Injection Client",
    "necrum/Main.class": "Necrum Client",
    "kys/bleach/Bleach": "Bleach Client",
    "Cracked by Buddy [SirJava]": "SirJava Crack Signature",
    "pw/latematt/xiv/value/ClampedValue.class": "Latematt Client",
    "10/10/80/41": "Kurium Injection Client",
    ".onetap.cc": "OneTap Client",
    "lemon.the.pvper.wrapper": "Lemon Injection Client",
    "durtaog/client/": "Durtaog Client",
    "xyz/Grand0x/gui": "Grand0x Client",
    "Veiv Client - WATERMARK": "Veiv Client",
    "DoubleClicker.class": "Double Clicker",
    "OLaperture/module/ModuleManager;": "Aperture Client",
    "batty/ui/server/ServerProxy": "Batty Coordinates Cheat",
    "Phoenix/Modules": "Phoenix Hacked Client",
    "Syphlex Forge.jar": "Syphlex Client",
    "FuncraftDelay": "Funcraft Client",
    "sallos/Sallos": "Sallos Client",
    "me/tojatta/clicker": "Tojatta Clicker",
    "Pandora\\Modules\\Combat": "Pandora Version Client",
    "maven/harambe": "Harambe Injection Client",
    "rebellion/tcpnod": "TCPNoDelay Cheat",
    "LabyMod_nngskjgkjsbkljsblkfblfbslk": "Labymod Invis Client",
    "assets/minecraft/flare": "Flare Version Client",
    "SSROCK_Velocity": "Regedit Mod Cheat",
    "/aristhena/": "Avix Injection Client",
    "dg82fo.pw": "Drek Client",
    "/azurwebsites": "Azure Client",
    "br/alkazuz/ircTwitterLogger.class": "Alkazuz Client",
    "spook:sword.png": "Spook Client",
    "leakforums.net.user665158.modules.SmoothAimbot": "Leakforums Client",
    "net\\latency\\speed\\ArtLatencyTw.class": "Ping Spoofer Mod",
    "net/wurstclient/features/Mod": "Wurst Version Client",
    "assets/minecraft/flux/": "Flux Client",
    "de.labymod.client.modules.impl.AimAssist": "Labymod Invis Client",
    "our/mod/asparagus": "Asparagus Mod Client",
    "assets/metro/": "Metro Version Client",
    "Triggerbot [G]": "G Client",
    "net/frozenorb/h2c/Clickhold.class": "Ethylene Client",
    "priority/hit/range/": "Priority Reach Mod",
    "mcmodding4k/fastbridge/": "FastBridge Mod",
    "tsissAmiA": "Syntax Client",
    "mousetweaks/Mousebutton.c": "MouseTweaks Cheat",
    "textures/Hekate/bg": "Hekate Version Client",
    "net/azurewebsites/thehen101/gc/mod/Triggerbot.class": "TheHen101 Client lol",
    "Cracked by 0x22": "0x22 Crack",
    "net/Cancer/ProxyClient": "Cancer Client",
    "3telltalegames.batmanthetelltaleseries_4p9dzwrngadje": "Batman Client",
    "cane8993jdsjad98sad9ssa9.altervista.org": "Casper Injection Client",
    "gorilla/Gorilla.class": "Gorilla Injection Client",
    "net/minecraft/client/main/a": "Hitler Version Client [OPTIFINE ONLY]",
    "me/tmih/yt/AC.class": "Tmih Autoclicker",
    "me.tyler.module.mods.Criticals": "Tyler Client",
    "onetap.cc": "OneTap Cheat",
    "phantom\\modules.properties": "Phantom Version Client",
    "Prevents Killaura from attacking teammates.": "Specific KillAura",
    "144.217.87.106": "Zuiy's IP",
    "Cracked by YGore": "Ygore Crack",
    "me/rowin/destruct": "Rowin's Client",
    "META-INF/byCCBlueX/LiquidBounce/": "LiquidBounce Mod Client",
    "CRACKED  BY FUSKED": "Fusked Crack",
    "assets/minecraft/huzuni/title.png": "Huzuni Version Client",
    "IIiIIiIiIiiiIiIiIiiI": "Spook Cracked",
    "zerodayboi/C": "ZeroDay Client",
    "reachmod/ReachMod.class": "Reach Mod",
    "Obfuscation by Allatori Obfuscator http://www.allatori.com'": "Allatori Obfuscation",
    "Bon mot de passe =)": "Some French cheat",
    "41/41/41/8/41": "Magenta Mod Client",
    "hypixel/xray/bypass/XRay$1": "Hypixel Xray Mod",
    "incognto": "Incognito Injection Client",
    "mojang/craft/block/w0mb4t/ac$m": "W0mb4t Client",
    "aperture/module": "Aperture Client",
    "me/zero/clarinet/Impact.class": "Zero Client",
    "io/netty/bestclient/": "Best Client",
    "Ethylene.jar": "Ethylene Client",
    "/kryptonite/": "Kryptonite Client",
    "the_fireplace/fluidity": "Fluidity Client",
    "glockteam": "Glock Client",
    "Minestrike/Cops & Crims ragebot.": "Ragebot Client",
    "me/aarow/": "Arrow Client",
    "legacy/gui/C": "Legacy Client",
    "libs.poisonex.nematode": "Poisonex Injection Client",
    "SAINTCLIENT": "Saint Client",
    "FakeYticolevClass123456.": "Skuuunksle100 Client",
    "supercheese200": "Cheese Client",
    "hasureclient": "Hasure Client",
    "johny9020_": "Johny's Client",
    "Horizon/Trism/": "Horizon Client",
    "textures/clint/background": "Clint Client",
    "WomboClient\\\\WomboClient": "Wombo Client",
    "com/S9_/": "SNINE Client",
    "dezztroy": "Dezz Troy Client",
    "sl/steeldood/bit/client/module/impl/combat/ModuleAutoclicker": "SteelDood Client",
    "AtomClient4Beta": "Atom Client",
    "paralyzed.module.modules": "Paralyzed Client",
    "zues/AltManager": "Zues Client",
    "SamerDEV%20Sub%20me": "SamerDev Client",
    "fr/reizam/deiramod/mods/Reach.class": "Reizam Client",
    "skillclient-logo.png": "Skill Client",
    "rupture/gui/aquaGui/RuptureClickGui.class": "Rupture Client",
    "Youre_Watching_Brazzers_": "Porn Client",
    "gui/rekt": "Rekt Client",
    "children/Gui": "Children Client",
    "yellowlight2": "Yellow Light Client",
    "me/tru3/base/modules/ModuleManager": "Krypto B1 Client",
    "porkchop_ERA": "Porkchop Client",
    "me/ygore/clint/Client.classUT": "YGORE CLINT CLIENT",
    "AVClientTrig": "AV CLient",
    "net/aristois/opencode/": "Aristois Client",
    "/provida/": "Provida Client",
    "package./caden/": "Chilli Caden Client",
    "net/minecraft/scooby/util/ModeUtils.class": "Scooby Client",
    "me/Austin/client/modules": "Austin Client",
    "RapeClient": "Rape Client",
    "Xerxes.jar": "Xerxes",
    "BITCHESS45": "Bitchess45 Client",
    "7.modulelist": "Seven Client",
    "io.wenzys": "Wenzys Injection Client",
    "AutoClicker.properties": "Generic Config Clicker",
    "optionspvp.txt": "Generic Config Combat",
    "xray.cfg": "Generic Config X-Ray",
    "isAimbotEnabled": "Generic Config Aimbot",
    "Aura_range": "Generic Config Reach",
    "Triggerbot_delay": "Generic Config Triggerbot",
    "modules/AutoClicker": "Generic Module AutoClicker",
    "modules/ForceField": "Generic Module ForceField",
    "modules/KillAura": "Generic Module KillAura",
    "modules/Velocity": "Generic Module Velocity",
    "autoclicker.class": "Generic Class Autoclicker",
    "PingSpoof.class": "Generic Class PingSpoof",
    "ReachMod.class": "Generic Class Reach",
    "AntiVoid.class": "Generic Class AntiVoid",
    "XRay.class": "Generic Class Xray",
    "aimbot.class": "Generic Class Aimbot",
    "TriggerBot.class": "Generic Class Triggerbot",
    "ChestStealer.class": "Generic Class ChestStealer",
    "SmoothAimbot.class": "Generic Class SmoothAimbot",
    "ForceField.class": "Generic Class ForceField",
    "AutoArmor.class": "Generic Class AutoArmor",
    "AimAssist.class": "Generic Class AimAssist",
    "AutoPearl.class": "Generic Class AutoPearl",
    "combat/AutoClicker": "Generic Combat Clicker",
    "combat/KillAura": "Generic Combat Aura",
    "combat/Velocity": "Generic Combat Velocity",
    "combat/Reach": "Generic Combat Reach",
    "combat/AimAssist": "Generic Combat AimAssist",
    "Self-Destructed successfully.": "Generic Self Destruct",
    "imgui_log.txt": "Generic ImGUI",
    "instrument.dll": "Confirmed Injection Client [FORGE ONLY]",
    "shell.rundll32": "Confirmed Injection Client",
    "InjectionDLL.dll": "Bee Clicker Injection",
    "->d=?ad=": "Vape Client V3",
    "D$@;D$DH": "Vape Client V2",
    "<>^L$0A": "Iridium Ghost",
    "xyz/gucciclient/gui": "Gucci Client",
    "trumpclientftw": "Bape Client",
    "ASM: 41.41.41.30.": "Magenta Client",
    "irid/a$a.class": "Irid Client",
    "me/aristhena/Gui": "Placebo Client",
    "Smooth Aim [UP]": "GClient",
    "omikronclientd": "Omikron Client",
    "2.47-KILL YOURSELF SLOWLY": "Vape Client V2",
    "czaarek99/injection": "Incognito Client",
    "10/10/80/30.classPK": "Kurium Client",
    "merge/start": "Merge Client",
    "veylkar/pepe/modes": "Pepe Client",
    "1.8-OptiFine_HD_U_D5": "Hitler Client",
    "tsglu/ke/AC.class": "Internal DoubleClicker",
    "me/tsglu/ke/HitBoxCommands": "Hitbox Client",
    "tsglu/ke/VuJOhtwfzHoTIHHHGbGI.class": "FastPlace Mod",
    "me.tsglu.ke.Safewalk": "SafeWalk Mod",
    "n%\u0007La": "Illegal Modfications",
    "me/massi/reach/Reach.class": "Reach Modifications",
    "net/reach/Verzide": "Reach Modifications",
    "dmillerw/ping/client/EventMod": "KB Modifications",
    "http://cane8993jdsjad98sad9ssa9.altervista.org": "Casper Client",
    "[TSGLuke] Aimbot speed set to": "NoHacks Module",
    "WomboClient\\WomboClient": "Wombo Client",
    ")<*=,T-U/Y0\u0002d3k5o7": "Reach Modifications",
    "_W_Y6": "Illegal Modifications",
    "pw/cinque/keystrokes/pp/Willy": "Willy Client",
    "AutoClicker.class": "Illegal Modifications",
    "javax.swing.JFrame": "Illegal Modifications",
    "modules/combat": "Illegal Modifications",
    "setTimerRate": "Illegal Modifications",
    "DoubleClicker.properties": "Illegal Modifications",
    "Cucklord inside!": "Anti SS Tool"
}

# DPS/tooling strings sometimes found in process memory
DPS_STRINGS = {
    ".exe!2019/03/14:20:01:24": "OP AutoClicker",
    ".exe!2016/05/30:16:33:32": "GS AutoClicker",
    ".exe!2016/04/18:16:56:55": "AutoClicker",
    ".exe!2018/11/09:01:13:38": "GhostBytes",
    ".exe!2019/07/05:07:17:50": "Speed AutoClicker",
}

KNOWN_BAD_HASHES = {
    # DoomsdayClient hashes (easy to bypass but better than ntg i guess 😭😭)
    "648ca4f9c2964bea3e91685a32e0381c803d648cc358b39ae4071fd3be77fed6": "DoomsdayClient",
    "9d110e6c54eb25e3b2683a94a1db579629ab4c7b5efb8e309da9be440bddb178": "DoomsdayClient",
}

def load_external_db(path="cheat_signatures.json"):
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            ILLEGAL_KEYWORDS[:] = list(set((data.get("illegal_keywords") or ILLEGAL_KEYWORDS)))
            JAVA_SIGNATURES.update(data.get("java_signatures") or {})
            DPS_STRINGS.update(data.get("dps_strings") or {})
            KNOWN_BAD_HASHES.update(data.get("known_bad_hashes") or {})
    except Exception:
        # anti-crash
        pass

# screenrecording software have overlay programs built in which can be used to bypass ss
RECORDERS = {
    "obs64.exe": "OBS",
    "obs32.exe": "OBS",
    "bdcam.exe": "Bandicam",
    "action.exe": "Action!",
    "dxtory.exe": "Dxtory",
    "nvidia share.exe": "NVIDIA ShadowPlay",
    "camtasia.exe": "Camtasia",
    "fraps.exe": "Fraps",
    "screencast.exe": "Screencast"
}

# ---------------------------
# helpers :)
# ---------------------------

def sha256_file(path, block=1<<20):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(block)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None

def safe_walk(top):
    # swallowing permission errors and skipping heavy system roots
    for root, dirs, files in os.walk(top, topdown=True, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d.lower() not in (
            "node_modules","$recycle.bin","windows","program files","program files (x86)")]
        yield root, files

def printable_strings(raw: bytes, min_len=4):
    out, run = [], []
    for ch in raw:
        if 32 <= ch <= 126:
            run.append(chr(ch))
        else:
            if len(run) >= min_len:
                out.append("".join(run))
            run = []
    if len(run) >= min_len:
        out.append("".join(run))
    return out


# memory reading via WinAPI (ctypes)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",      wintypes.LPVOID),
        ("AllocationBase",   wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",       ctypes.c_size_t),
        ("State",            wintypes.DWORD),
        ("Protect",          wintypes.DWORD),
        ("Type",             wintypes.DWORD)
    ]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                              wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                           ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                           ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t
CloseHandle = kernel32.CloseHandle

def _read_region(hproc, address, size, limit=16*1024*1024):
    """
    Attempt to read a memory region from another process.
    Skips unreadable/guarded pages gracefully.
    """
    size = min(size, limit)
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    success = ReadProcessMemory(hproc, ctypes.c_void_p(address),
                                buf, size, ctypes.byref(read))
    if not success:
        # skip silently if region not readable
        return b""
    return bytes(buf[:read.value])

def dump_process_strings(pid, min_length=5, max_total_read=256*1024*1024):
  #dump printable strings from memory of mc and cross-checks flags against javaW strings from config
    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        hProc = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProc:
            return [], "permission_denied"

        addr = 0
        total = 0
        collected = []
        mbi = MEMORY_BASIC_INFORMATION()

        while True:
            res = VirtualQueryEx(hProc, ctypes.c_void_p(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not res:
                break

            guard = (mbi.Protect & PAGE_GUARD) or (mbi.Protect & PAGE_NOACCESS)
            if (mbi.State == MEM_COMMIT) and not guard:
                chunk = _read_region(hProc, mbi.BaseAddress, mbi.RegionSize)
                if chunk:
                    total += len(chunk)
                    collected.extend(printable_strings(chunk, min_len=min_length))
                    if total >= max_total_read:
                        break

            addr += mbi.RegionSize
            if addr <= 0 or addr > 0x7FFFFFFFFFFF:
                break

        CloseHandle(hProc)
        return collected, ""
    except psutil.NoSuchProcess:
        return [], "no_process"
    except Exception:
        return [], "permission_denied"

# scanners


def minecraft_dirs():
    """Common launcher roots; only existing paths are returned."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    localapp = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")

    dirs = [
        # mojang / microsoft store
        os.path.join(appdata, ".minecraft"),
        os.path.join(localapp, "Packages", "Microsoft.MinecraftUWP_8wekyb3d8bbwe"),

        # popular 3rd party lauchers
        os.path.join(localapp, "PrismLauncher"),
        os.path.join(localapp, "Programs", "PrismLauncher"),
        os.path.join(localapp, "MultiMC"),
        os.path.join(appdata, ".technic"),
        os.path.join(appdata, ".gdlauncher"),
        os.path.join(appdata, ".curseforge"),
        os.path.join(appdata, "curseforge", "minecraft"),
        os.path.join(appdata, "Overwolf", "CurseForge", "minecraft"),
        os.path.join(appdata, ".minecraft", "mods"),
        os.path.join(appdata, "ATLauncher"),
        os.path.join(localapp, "LunarClient"),
        os.path.join(appdata, "BadlionClient"),
        os.path.join(appdata, "Feather"),
        os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "CurseForge"),
        # portable launchers
        os.path.join(home, "Downloads", "MultiMC"),
        os.path.join(home, "Desktop", "MultiMC"),
    ]
    uniq, seen = [], set()
    for d in dirs:
        if d and d.lower() not in seen and os.path.isdir(d):
            uniq.append(d); seen.add(d.lower())
    return uniq

class MemoryScanner:
    def __init__(self):
        self.findings = {"pid": None, "username_hint": None,
                         "sig_hits": [], "dps_hits": [], "generic_hits": []}

    @staticmethod
    def _find_pid_by_name(name_substr):
        for p in psutil.process_iter(attrs=["pid", "name"]):
            try:
                if p.info["name"] and name_substr.lower() in p.info["name"].lower():
                    return p.info["pid"]
            except Exception:
                continue
        return None

    def scan_javaw(self):
        pid = self._find_pid_by_name("javaw")
        self.findings["pid"] = pid
        if not pid:
            return self.findings

        strings, err = dump_process_strings(pid, min_length=5)
        if err:
            self.findings["error"] = err
            return self.findings

        low = [s.lower() for s in strings]
        low_set = set(low)

        for sig, label in JAVA_SIGNATURES.items():
            s = sig.lower()
            if any(s in x for x in low_set):
                self.findings["sig_hits"].append({"signature": sig, "label": label})

        for sig, label in DPS_STRINGS.items():
            s = sig.lower()
            if any(s in x for x in low_set):
                self.findings["dps_hits"].append({"signature": sig, "label": label})

        generic = set()
        for kw in ILLEGAL_KEYWORDS:
            if any(kw in x for x in low_set):
                generic.add(kw)
        self.findings["generic_hits"] = sorted(list(generic))

        # very basic username heuristics
        for s in strings:
            sl = s.lower()
            if "logged in as" in sl or "username" in sl:
                m = re.search(r"(?:as|username)\s*[:=]\s*([A-Za-z0-9_]{3,16})", s, re.IGNORECASE)
                if m:
                    self.findings["username_hint"] = m.group(1)
                    break

        return self.findings

class DiskScanner:
    EXTENSIONS = (".jar", ".zip", ".rar", ".7z", ".dll", ".exe", ".class")

    def __init__(self, known_hashes=None):
        self.known_hashes = known_hashes or {}
        self.findings = {"roots": [], "flagged_by_name": [], "flagged_by_hash": [], "mods_index": []}

    def scan(self):
        roots = minecraft_dirs()
        self.findings["roots"] = roots
        for root in roots:
            for base, files in safe_walk(root):
                for fn in files:
                    path = os.path.join(base, fn)
                    low = fn.lower()

                    # filename-based flags 
                    if low.endswith(self.EXTENSIONS) and any(k in low for k in ILLEGAL_KEYWORDS):
                        self.findings["flagged_by_name"].append({"path": path, "reason": "keyword"})

                    # hash-based flags
                    if low.endswith(self.EXTENSIONS) and (low.endswith(".jar") or low.endswith(".zip")
                                                          or low.endswith(".dll") or low.endswith(".exe")):
                        h = sha256_file(path)
                        if h and h in self.known_hashes:
                            self.findings["flagged_by_hash"].append({"path": path, "sha256": h, "label": self.known_hashes[h]})

                    # index .jar/.zip/.class presence (for operator review)
                    if low.endswith((".jar",".zip",".class")):
                        self.findings["mods_index"].append(path)
        return self.findings

class LogParser:
    def __init__(self):
        self.findings = {"log_roots": [], "suspicious_markers": [], "servers": []}

    def _mc_logs(self):
        roots = []
        for d in minecraft_dirs():
            logs = os.path.join(d, "logs")
            if os.path.isdir(logs):
                roots.append(logs)
        return roots

    def _parse_log_stream(self, name, stream):
        suspicious = []
        servers = set()
        try:
            for raw in stream:
                line = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else raw
                low = line.lower()
                # suspicious markers
                if any(k in low for k in ILLEGAL_KEYWORDS) or \
                   any(k in low for k in ("baritone","liquidbounce","wurst","meteor","impact","inertia")):
                    suspicious.append(line.strip())

                # server entries
                # "Connecting to <host>, <port>" etc
                m = re.search(r"connecting to\s+([A-Za-z0-9\.\-]+),\s*(\d+)", low)
                if m:
                    servers.add(f"{m.group(1)}:{m.group(2)}")
        except Exception:
            pass
        return suspicious, sorted(servers)

    def scan(self):
        roots = self._mc_logs()
        self.findings["log_roots"] = roots
        seen_servers = set()
        for root in roots:
            # latest.log
            latest = os.path.join(root, "latest.log")
            if os.path.isfile(latest):
                try:
                    with open(latest, "rb") as f:
                        susp, servers = self._parse_log_stream("latest.log", f)
                        self.findings["suspicious_markers"].extend(susp)
                        seen_servers.update(servers)
                except Exception:
                    pass
            # archived .gz filessssss
            for gz in glob.glob(os.path.join(root, "*.gz")):
                try:
                    with gzip.open(gz, "rb") as f:
                        susp, servers = self._parse_log_stream(os.path.basename(gz), f)
                        self.findings["suspicious_markers"].extend(susp)
                        seen_servers.update(servers)
                except Exception:
                    continue
        self.findings["servers"] = sorted(list(seen_servers))
        # remove excessive markers to keep JSON/log readable
        if len(self.findings["suspicious_markers"]) > 2000:
            self.findings["suspicious_markers"] = self.findings["suspicious_markers"][:2000] + ["...(truncated)"]
        return self.findings

class DeletedFileScanner:
    def __init__(self):
        self.findings = {"prefetch_suspects": [], "pca_deleted_paths": [], "recycle_bin_hits": []}

    @staticmethod
    def scan_prefetch():
        hits = []
        windir = os.environ.get("WINDIR", r"C:\Windows")
        prefetch = os.path.join(windir, "Prefetch")
        if not os.path.isdir(prefetch):
            return hits
        try:
            for fn in os.listdir(prefetch):
                low = fn.lower()
                if (low.endswith(".pf")) and (".exe-" in low or ".jar-" in low):
                    if any(k in low for k in ILLEGAL_KEYWORDS) or any(k in low for k in ("java","javaw","minecraft","launcher")):
                        hits.append(os.path.join(prefetch, fn))
        except PermissionError:
            print(Fore.RED + "    - Access denied reading Prefetch (skipping)." + Style.RESET_ALL)
            return []
        except Exception as e:
            print(Fore.RED + f"    - Error reading Prefetch: {e}" + Style.RESET_ALL)
            return []
        return hits


    @staticmethod
    def _pca_explorer_deleted():
        """
        string scan of PCA/Explorer persistence files for absolute paths to .exe/.jar that no longer exist.
        We scan common locations:
          - %LOCALAPPDATA%\Microsoft\Windows\PCA\
          - %LOCALAPPDATA%\Microsoft\Windows\Explorer\
        """
        suspects = set()
        home = os.path.expanduser("~")
        localapp = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        roots = [
            os.path.join(localapp, "Microsoft", "Windows", "PCA"),
            os.path.join(localapp, "Microsoft", "Windows", "Explorer"),
        ]
        path_rx = re.compile(r"[a-z]:\\[^:*?\"<>|]{3,}\.(exe|jar)", re.IGNORECASE)
        for r in roots:
            if not os.path.isdir(r):
                continue
            for base, files in safe_walk(r):
                for fn in files:
                    path = os.path.join(base, fn)
                    try:
                        with open(path, "rb") as f:
                            data = f.read()
                        for s in printable_strings(data, min_len=6):
                            for m in path_rx.finditer(s):
                                p = m.group(0)
                                if not os.path.isfile(p):
                                    suspects.add(p)
                    except Exception:
                        continue
        return sorted(suspects)

    @staticmethod
    def _recycle_bin_hits():
        hits = []
        drive = os.path.splitdrive(os.environ.get("SystemDrive", "C:"))[0] + "\\"
        rb_root = os.path.join(drive, "$Recycle.Bin")
        if not os.path.isdir(rb_root):
            return hits
        for root, _, files in os.walk(rb_root):
            for fn in files:
                low = fn.lower()
                if low.endswith(".exe") or low.endswith(".jar"):
                    hits.append(os.path.join(root, fn))
        return hits

    def scan(self):
        self.findings["prefetch_suspects"] = self.scan_prefetch()
        self.findings["pca_deleted_paths"] = self._pca_explorer_deleted()
        self.findings["recycle_bin_hits"] = self._recycle_bin_hits()
        return self.findings

class JNativeHookScanner:
    def __init__(self):
        self.findings = {"temp_dlls": []}

    def scan(self):
        temp = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")
        if os.path.isdir(temp):
            try:
                for f in os.listdir(temp):
                    if f.lower().endswith(".dll") and "jnativehook" in f.lower():
                        self.findings["temp_dlls"].append(os.path.join(temp, f))
            except Exception:
                pass
        return self.findings

class EnvironmentScanner:
    def __init__(self):
        self.findings = {"recorders_running": []}

    def scan(self):
        procs = {}
        for p in psutil.process_iter(attrs=["pid", "name"]):
            try:
                name = (p.info["name"] or "").lower()
                procs[name] = p.info["pid"]
            except Exception:
                continue
        for exe, label in RECORDERS.items():
            if exe.lower() in procs:
                self.findings["recorders_running"].append({"process": exe, "label": label, "pid": procs[exe.lower()]})
        return self.findings

# ---------------------------
# classification and reporting
# ---------------------------

class Classifier:
    """
      - DIRTY if:
          * any java memory signature hit, OR
          * any known-bad hash on disk, OR
          * JNativeHook DLL(s) found in %TEMP%
      - SUSPICIOUS if:
          * generic keywords in memory, OR
          * suspicious log markers, OR
          * Prefetch/Deleted/RecycleBin hits suggest cheat tools, OR
          * suspicious filenames on disk
        (Recorders running are contextual, not damning.)
      - CLEAN otherwise.
    """
    def decide(self, all_findings):
        reasons = []
        mem = all_findings.get("memory", {})
        disk = all_findings.get("disk", {})
        logs = all_findings.get("logs", {})
        deleted = all_findings.get("deleted", {})
        jnh = all_findings.get("jnativehook", {})
        envf = all_findings.get("environment", {})

        # DIRTY
        if mem.get("sig_hits"):
            reasons.append("Injected signatures in javaw memory")
        if disk.get("flagged_by_hash"):
            reasons.append("Detected known-bad hashes on disk")
        if jnh.get("temp_dlls"):
            reasons.append("JNativeHook-style DLL(s) present in %TEMP%")

        if reasons:
            return "DIRTY / HACKING", reasons

        # SUSPICIOUS
        susp = False
        if mem.get("generic_hits"):
            susp = True; reasons.append("Generic cheat keywords present in javaw memory")
        if logs.get("suspicious_markers"):
            susp = True; reasons.append("Suspicious markers found in logs")
        if disk.get("flagged_by_name"):
            susp = True; reasons.append("Suspicious filenames found in Minecraft directories")
        if deleted.get("prefetch_suspects") or deleted.get("pca_deleted_paths") or deleted.get("recycle_bin_hits"):
            susp = True; reasons.append("Deleted/Prefetch/RecycleBin executables detected")
        if envf.get("recorders_running"):
            reasons.append("Screen recorder/overlay software running")

        if susp:
            return "SUSPICIOUS (LIKELY CHEATING)", reasons or ["One or more suspicious indicators present"]
        return "CLEAN", ["No cheating indicators detected"]

class Reporter:
    def __init__(self, out_dir=None):
        if out_dir:
            self.out_dir = out_dir
        else:
            self.out_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            if not os.path.isdir(self.out_dir):
                try:
                    os.makedirs(self.out_dir, exist_ok=True)
                except Exception:
                    self.out_dir = os.getcwd()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.txt_path = os.path.join(self.out_dir, f"mc_anticheat_report_{ts}.txt")
        self.json_path = os.path.join(self.out_dir, f"mc_anticheat_report_{ts}.json")

    def _sanitize(self, obj, maxlen=500000):
        try:
            s = json.dumps(obj, ensure_ascii=False)
            if len(s) > maxlen:
                return json.loads(s[:maxlen])
            return obj
        except Exception:
            return obj

    def write(self, all_findings, verdict, reasons):
        # TXT
        with open(self.txt_path, "w", encoding="utf-8") as f:
            f.write("=== Minecraft Anti-Cheat / Screenshare Report ===\n")
            f.write(f"Version: {TOOL_VERSION}\n")
            f.write(f"Scan ID: {SCAN_ID}\n")
            f.write(f"Host: {platform.node()} | OS: {platform.platform()}\n")
            f.write(f"Started: {START_TS.isoformat()}\n")
            f.write(f"Finished: {datetime.now().isoformat()}\n")
            f.write(f"Verdict: {verdict}\n")
            f.write("Reasons:\n")
            for r in reasons:
                f.write(f"  - {r}\n")
            f.write("\n--- Findings ---\n")
            for section, data in all_findings.items():
                f.write(f"\n[{section.upper()}]\n")
                try:
                    f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
                except Exception:
                    f.write(str(data) + "\n")

        # JSON
        payload = {
            "meta": {
                "version": TOOL_VERSION,
                "scan_id": SCAN_ID,
                "host": platform.node(),
                "os": platform.platform(),
                "started": START_TS.isoformat(),
                "finished": datetime.now().isoformat(),
            },
            "verdict": verdict,
            "reasons": reasons,
            "findings": self._sanitize(all_findings)
        }
        with open(self.json_path, "w", encoding="utf-8") as jf:
            json.dump(payload, jf, indent=2, ensure_ascii=False)
        return self.txt_path, self.json_path

# console (what user sees)

def main():
    ascii_banner = r"""
                                      $$\                 $$\                         $$\ 
                                      $  |                $$ |                        $$ |
 $$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\\_/$$$$$$$\       $$$$$$\    $$$$$$\   $$$$$$\  $$ |
 \____$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  _____|      \_$$  _|  $$  __$$\ $$  __$$\ $$ |
 $$$$$$$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |\$$$$$$\          $$ |    $$ /  $$ |$$ /  $$ |$$ |
$$  __$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | \____$$\         $$ |$$\ $$ |  $$ |$$ |  $$ |$$ |
\$$$$$$$ |\$$$$$$$ |\$$$$$$  |\$$$$$$  |$$$$$$$  |        \$$$$  |\$$$$$$  |\$$$$$$  |$$ |
 \_______| \____$$ | \______/  \______/ \_______/          \____/  \______/  \______/ \__|
                $$ |                                                                      
                $$ |                                                                      
                \__|                                                           \______/                                         
    """
    print(Fore.MAGENTA + ascii_banner + Style.RESET_ALL)

    print(Fore.CYAN + f"[+] Minecraft Anti-Cheat / Screenshare Tool v{TOOL_VERSION} — Scan {SCAN_ID}" + Style.RESET_ALL)


    load_external_db()  # best-effort

    all_findings = {}

    # 1) Memory
    print(Fore.YELLOW + "[*] Scanning javaw.exe memory..." + Style.RESET_ALL)
    mem = MemoryScanner().scan_javaw()
    all_findings["memory"] = mem
    pid = mem.get("pid")
    if not pid:
        print("    - javaw.exe not found (Minecraft might not be running). Continuing...")
    elif mem.get("error") == "permission_denied":
        print("    - Permission denied reading javaw memory (try running as admin).")

    # 2) Disk
    print(Fore.YELLOW + "[*] Scanning Minecraft directories (names + hashes)..." + Style.RESET_ALL)
    disk = DiskScanner(known_hashes=KNOWN_BAD_HASHES).scan()
    all_findings["disk"] = disk

    # 3) Logs
    print(Fore.YELLOW + "[*] Parsing Minecraft logs..." + Style.RESET_ALL)
    logs = LogParser().scan()
    all_findings["logs"] = logs

    # 4) Deleted EXE/JAR: Prefetch, PCA/Explorer, Recycle Bin
    print(Fore.YELLOW + "[*] Checking Prefetch / PCA / Explorer / Recycle Bin for deleted EXE/JAR traces..." + Style.RESET_ALL)
    deleted = DeletedFileScanner().scan()
    all_findings["deleted"] = deleted

    # 5) JNativeHook in %TEMP%
    print(Fore.YELLOW + "[*] Scanning %TEMP% for JNativeHook DLLs..." + Style.RESET_ALL)
    jnh = JNativeHookScanner().scan()
    all_findings["jnativehook"] = jnh

    # 6) Environment: Recorders/Overlays
    print(Fore.YELLOW + "[*] Checking for screen recorders/overlays..." + Style.RESET_ALL)
    envf = EnvironmentScanner().scan()
    all_findings["environment"] = envf

    # final verdict
    verdict, reasons = Classifier().decide(all_findings)
    print(Fore.GREEN + f"[+] Verdict: {verdict}" + Style.RESET_ALL)
    for r in reasons:
        print("    - " + r)

    # Report/logs
    reporter = Reporter()
    txt, js = reporter.write(all_findings, verdict, reasons)

    print(Fore.CYAN + f"\n[+] Reports saved to: {reporter.out_dir}" + Style.RESET_ALL)
    print("    - " + txt)
    print("    - " + js)


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        exit_code = 1
    except Exception as e:
        print(Fore.RED + "[!] Unhandled error: " + str(e) + Style.RESET_ALL)
        traceback.print_exc()
        exit_code = 2

    input("\nPress Enter to close...")
    sys.exit(exit_code)

    #aquoric2
    #https://aquoric.github.io/
