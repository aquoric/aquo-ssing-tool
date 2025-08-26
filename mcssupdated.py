

# R=scans: memory scan, disk scan, logs, process list, JNativeHook, deleted .EXE's AND jars (.jar)
# Runs in the same console; no UAC prompts. Pure ctypes for memory reads.

import os, sys, re, gzip, io, time, ctypes, subprocess, hashlib, glob
import ctypes.wintypes as wintypes
from collections import defaultdict, Counter
from datetime import datetime
from tqdm import tqdm
import winreg

# ----------------------------
# console colors
# ----------------------------
RED = "\033[91m"
RESET = "\033[0m"

# ----------------------------
# config & signatures
# ----------------------------


recordingSoftwares = {
    'bdcam.exe':'Bandicam', 'action.exe':'Action', 'obs64.exe':'OBS', 'obs32.exe':'OBS',
    'dxtory.exe':'Dxtory', 'nvidia share.exe':'Geforce Experience', 'camtasia.exe':'Camtasia',
    'fraps.exe':'Fraps', 'screencast.exe':'Screencast'
}
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(SCRIPT_DIR, f"mc_ss_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

def log_line(text):
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[!] Failed to write log: {e}")
# dps strings (credit to astro)
dpsStrings = {
    '.exe!2019/03/14:20:01:24': 'OP AutoClicker',
    '.exe!2016/05/30:16:33:32': 'GS AutoClicker',
    '.exe!2016/04/18:16:56:55': 'AutoClicker',
    '.exe!2018/11/09:01:13:38': 'GhostBytes',
    '.exe!2019/07/05:07:17:50': 'Speed AutoClicker'
}

# javaW strings (credit to astro)
javawStrings = {
    "net/impactclient": "Impact Client",
    "SqtkUVg": "Vape v3",
    "erouax/instavape": "Wax Vape Mod",
    "com/sun/jna/z/a/e/a/a/a/f": "Vape Cracked",
    "hakery.c": "Latemod Injection Client",
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

# keywords that flag illegal mods when found in filenames
ILLEGAL_KEYWORDS = [
    "xray","wurst","meteor","aristois","impact","liquidbounce","inertia",
    "sigma","kronos","killaura","reachmod","autoclick","aimassist","esp",
    "flux","huzuni","wape","vape","rinject","incognito","bleach","bape",
    "kryp","ethylen","lemonade","pepe","phantom","verzide","mouseTweaks" # add/trim as desired
]

# doomsday hashes, but ts kinda bad for detection since doomsday gives an option to randomize filesizes which changes the hash
known_bad_hashes = {
     "648ca4f9c2964bea3e91685a32e0381c803d648cc358b39ae4071fd3be77fed6": "doomsdayclient",
     "9d110e6c54eb25e3b2683a94a1db579629ab4c7b5efb8e309da9be440bddb178": "doomsdayclient"
}

# ----------------------------
# checking for recording software (to prevent bypassing screenshare by recording the ss session)
# ----------------------------

def detect_recorders():
    procs = tasklist()
    found = []
    for p in procs:
        img = (p["image"] or "").lower()
        if img in recordingSoftwares:
            found.append((img, recordingSoftwares[img]))
    return found
# ----------------------------
# helpers: files, hashing, search
# ----------------------------

def iter_files(base, exts=None):
    exts = [e.lower() for e in (exts or [])]
    for root, dirs, files in os.walk(base, topdown=True):
        # Skip heavy dirs
        dirs[:] = [d for d in dirs if d.lower() not in ("node_modules","$recycle.bin","windows","program files","program files (x86)")]
        for f in files:
            fp = os.path.join(root, f)
            if exts:
                if any(f.lower().endswith(e) for e in exts):
                    yield fp
            else:
                yield fp

def sha256_of_file(path, max_bytes=None):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            if max_bytes:
                h.update(f.read(max_bytes))
            else:
                for chunk in iter(lambda: f.read(1024*1024), b""):
                    h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ----------------------------
# Windows process utilities (no psutil alternative)
# ----------------------------

def tasklist():
    try:
        out = subprocess.check_output(["tasklist", "/fo", "csv", "/nh"], creationflags=0x08000000)
        text = out.decode("utf-8", errors="ignore").splitlines()
        rows = []
        for line in text:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                rows.append({"image": parts[0], "pid": int(parts[1]) if parts[1].isdigit() else None})
        return rows
    except Exception:
        return []

def get_pid_by_name(name, service=False):
    name = name.lower()
    for row in tasklist():
        if row["image"].lower() == name:
            return row["pid"]
    return None

# ----------------------------
# PURE ctypes memory reader
# ----------------------------

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

def _read_region(hproc, address, size):
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(hproc, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
        return b""
    return bytes(buf[: read.value])

def dump_process_strings(pid, min_length=4, max_address=0x7FFFFFFFFFFF):
    findings = []
    hproc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hproc:
        return None, "permission_denied"

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    scanned = 0
    while addr < max_address:
        res = kernel32.VirtualQueryEx(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not res:
            addr += 0x1000
            continue
        commit = (mbi.State == MEM_COMMIT)
        protected = (mbi.Protect & PAGE_GUARD) or (mbi.Protect == PAGE_NOACCESS)
        if commit and not protected and mbi.RegionSize:
            data = _read_region(hproc, addr, mbi.RegionSize)
            if data:
                text = data.decode("latin-1", errors="ignore")
                for m in re.findall(r"[ -~]{%d,}" % min_length, text):
                    findings.append(m)
        addr += mbi.RegionSize
        scanned += mbi.RegionSize
        if scanned > (256 * 1024 * 1024):  # ~256MB cap
            break

    kernel32.CloseHandle(hproc)
    return findings, None

# ----------------------------
# JNativeHook DLL check (temp folder)
# ----------------------------

def check_jnativehook():
    temp = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")
    found = []
    try:
        for f in os.listdir(temp):
            if f.endswith(".dll") and "JNativeHook" in f:
                found.append(os.path.join(temp, f))
    except Exception:
        pass
    return found


#------
#file hashing
#------
def file_hash(path, algo="sha256"):
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ----------------------------
# Deleted EXE discovery methods
# ----------------------------

# Attempt PCA + Explorer-based method (astro ac method), fallback to error if missing 

def get_deleted_executables_pca():
    try:
        return get_deleted_executables()  # existing function from original script
    except NameError:
        return {}, "missing_pids"
    except PermissionError:
        return {}, "permission_denied"
    except Exception:
        return {}, "error"

# Prefetch-based deleted EXE scan (my method)
def scan_prefetch_deleted_exes():
    results = []
    pf_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
    if not os.path.isdir(pf_dir):
        return results
    for pf in glob.glob(os.path.join(pf_dir, "*.pf")):
        base = os.path.basename(pf).split("-")[0] + ".exe"
        found_path = None
        for d in os.environ["PATH"].split(os.pathsep):
            candidate = os.path.join(d, base)
            if os.path.exists(candidate):
                found_path = candidate
                break
        if not found_path:
            results.append((base, "deleted", None))
        else:
            h = file_hash(found_path)
            if h and h in known_bad_hashes:
                results.append((base, "bad_hash", h))
    return results

# Attached-image inspired approach: parse Prefetch hashes & Explorer fallback (my method)

def scan_prefetch_hashes():
    results = []
    pf_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
    if not os.path.isdir(pf_dir):
        return results
    for pf in glob.glob(os.path.join(pf_dir, "*.pf")):
        try:
            base = os.path.basename(pf).split("-")[0] + ".exe"
            h = file_hash(pf)
            if h and h in known_bad_hashes:
                results.append((base, "prefetch_hash_match", h))
        except Exception:
            continue
    return results

# Recycle Bin scanning helpers
def sid2user(sid):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid)
        value, _ = winreg.QueryValueEx(key, 'ProfileImagePath')
        user = value.split('\\')[-1]
        return user
    except Exception:
        return sid

def returnDir():
    dirs=['C:\\$Recycle.Bin', 'C:\\Recycler', 'C:\\Recycled']
    for recycleDir in dirs:
        if os.path.isdir(recycleDir):
            return recycleDir
    return None

def scan_recycle_bin_deleted_exes():
    results = []
    recycleDir = returnDir()
    if not recycleDir:
        return results
    try:
        for sid in os.listdir(recycleDir):
            user = sid2user(sid)
            path = os.path.join(recycleDir, sid)
            if not os.path.isdir(path):
                continue
            for f in os.listdir(path):
                fp = os.path.join(path, f)
                if f.lower().endswith(".exe"):
                    h = file_hash(fp)
                    if not os.path.exists(fp):
                        results.append((f, user, "deleted", None))
                    elif h and h in known_bad_hashes:
                        results.append((f, user, "bad_hash", h))
                    else:
                        results.append((f, user, "present", h))
    except Exception:
        pass
    return results


# ----------------------------
# Disk scan: Minecraft dirs / jars / mods
# ----------------------------

def minecraft_paths():
    paths = []
    user = os.path.expanduser("~")
    appdata = os.getenv("APPDATA") or os.path.join(user, "AppData", "Roaming")
    localappdata = os.getenv("LOCALAPPDATA") or os.path.join(user, "AppData", "Local")
    documents = os.path.join(user, "Documents")

    # mojang launcher
    paths.append(os.path.join(appdata, ".minecraft"))

    # microsoft store
    paths.append(os.path.join(localappdata, "Packages", "Microsoft.MinecraftUWP_8wekyb3d8bbwe"))

    # popular 3rd-party launchers
    launcher_dirs = [
        "MultiMC", "PrismLauncher", "PolyMC", "ATLauncher", "Technic", "TLauncher",
        "SKLauncher", "HMCL", "LunarClient", "Feather", "Badlion Client",
        "Salwyrr", "GDLauncher", "VoidLauncher", "CrystalLauncher", "LabyMod"
    ]
    for launcher in launcher_dirs:
        paths.append(os.path.join(user, launcher))

    # CurseForge
    paths.append(os.path.join(documents, "CurseForge", "minecraft"))
    paths.append(os.path.join(appdata, "curseforge", "minecraft"))

    # GDLauncher (new + old)
    paths.append(os.path.join(appdata, "gdlauncher_next"))
    paths.append(os.path.join(appdata, "GDLauncher"))

    # Overwolf (CurseForge wrapper)
    paths.append(os.path.join(appdata, "Overwolf", "CurseForge", "minecraft"))

    # known portable dirs in Downloads/Desktop
    paths.append(os.path.join(user, "Downloads", "MultiMC"))
    paths.append(os.path.join(user, "Desktop", "MultiMC"))

    return [p for p in paths if os.path.isdir(p)]

def safe_iter_files(base, exts=None):
    exts = [e.lower() for e in (exts or [])]
    for root, dirs, files in os.walk(base, topdown=True, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d.lower() not in (
            "node_modules","$recycle.bin","windows","program files","program files (x86)")]
        for f in files:
            fp = os.path.join(root, f)
            if not exts or any(f.lower().endswith(e) for e in exts):
                yield fp

def list_mods_and_flag_illegal():
    mods_found = []
    flagged = []
    paths = minecraft_paths()

    for base in tqdm(paths, desc="Scanning Minecraft installations", unit="dir"):
        all_files = list(safe_iter_files(base, exts=[".jar", ".zip"]))
        for fp in tqdm(all_files, desc=f"  -> {os.path.basename(base)}", unit="file", leave=False):
            mods_found.append(fp)
            modname = os.path.basename(fp).lower()
            if any(k in modname for k in ILLEGAL_KEYWORDS):
                flagged.append((fp, "keyword"))
            h = sha256_of_file(fp, max_bytes=1024*1024)
            if h and h in known_bad_hashes:
                flagged.append((fp, f"hash:{known_bad_hashes[h]}"))
    return mods_found, flagged

# ----------------------------
# Recycle Bin scan: EXEs + JARs
# ----------------------------

def scan_recycle_bin_deleted_files():
    results = []
    recycleDir = returnDir()
    if not recycleDir:
        return results
    try:
        for sid in os.listdir(recycleDir):
            user = sid2user(sid)
            path = os.path.join(recycleDir, sid)
            if not os.path.isdir(path):
                continue
            for f in os.listdir(path):
                fp = os.path.join(path, f)
                lower = f.lower()
                if lower.endswith(".exe") or lower.endswith(".jar"):
                    h = file_hash(fp)
                    status = "present"
                    reason = None

                    if not os.path.exists(fp):
                        status = "deleted"
                    elif h and h in known_bad_hashes:
                        status = "bad_hash"; reason = h
                    elif any(k in lower for k in ILLEGAL_KEYWORDS):
                        status = "illegal_keyword"; reason = next(k for k in ILLEGAL_KEYWORDS if k in lower)

                    results.append((f, user, status, reason))
    except Exception:
        pass
    return results

# ----------------------------
# Logs scan: joined servers & suspicious
# ----------------------------

SERVER_RE = re.compile(r"(?:Connecting|Connected)\s+to\s+([^\s,]+)", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b")
SUS_LOG_MARKERS = [
    "baritone", "liquidbounce", "impact", "meteor", "wurst", "killaura", "reach",
    "autoclick", "aimassist", "xray", "bleach", "incognito", "esp"
]

def find_logs_dirs():
    dirs = []
    for p in minecraft_paths():
        logs = os.path.join(p, "logs")
        if os.path.isdir(logs):
            dirs.append(logs)
    return dirs

def read_text_or_gz(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                return f.read().decode("utf-8", errors="ignore")
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
    except Exception:
        return ""

def scan_logs():
    servers = set()
    suspicious_hits = []
    dirs = find_logs_dirs()
    for d in tqdm(dirs, desc="Scanning log folders", unit="dir"):
        for fp in glob.glob(os.path.join(d, "latest.log")) + glob.glob(os.path.join(d, "*.gz")):
            text = read_text_or_gz(fp)
            if not text:
                continue
            for m in SERVER_RE.findall(text):
                servers.add(m.strip())
            for line in text.splitlines():
                l = line.lower()
                if any(k in l for k in SUS_LOG_MARKERS):
                    suspicious_hits.append((fp, line[:160]))
            for m in IP_RE.findall(text):
                servers.add(m.strip())
    return sorted(servers), suspicious_hits
# ----------------------------
# Classification / Conclusion
# ----------------------------

def classify(findings):
    score = 0
    reasons = []

    if findings["memory"].get("sig_hits"):
        score += 6
        reasons.append("Injected/hacked-client signatures in javaw memory")
    if findings["memory"].get("dps_hits"):
        score += 5
        reasons.append("DPS autoclicker signatures in process memory")

    if findings["mods_flagged"]:
        score += 3
        reasons.append("Illegal/suspicious mods present on disk")

    if findings["logs_suspicious"]:
        score += 2
        reasons.append("Suspicious markers found in logs")

    if findings["jnativehook"]:
        score += 2
        reasons.append("JNativeHook DLL found in Temp (possible autoclicker)")

    if findings["deleted_exes"]:
        score += 2
        reasons.append("Recently executed then deleted EXEs observed")

    if score >= 6:
        verdict = "DIRTY / HACKING"
    elif score >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return verdict, reasons

# ----------------------------
# Memory scan: javaw.exe for known strings (javaW string from config) & DPS AND generic cheat keywords (can misflag)
# ----------------------------

def scan_javaw_memory(javaw_pid):
    mem_findings = []
    dps_hits = []
    sig_hits = []
    keywords_hits = []

    strings, err = dump_process_strings(javaw_pid, min_length=5)
    if err == "permission_denied":
        return {"error": "permission_denied"}

    strings = strings or []
    sset = set(s.lower() for s in strings)

    for k, name in dpsStrings.items():
        if any(k.lower() in s for s in sset):
            dps_hits.append((k, name))

    for sig, label in javawStrings.items():
        if any(sig.lower() in s for s in sset):
            sig_hits.append((sig, label))

    for kw in ILLEGAL_KEYWORDS:
        if any(kw in s for s in sset):
            keywords_hits.append(kw)

    mc_user = None
    for s in strings:
        if "logged in as" in s.lower() or "username" in s.lower():
            m = re.search(r"(?:as|username)\s*[:=]\s*([A-Za-z0-9_]{3,16})", s, re.IGNORECASE)
            if m:
                mc_user = m.group(1)
                break

    return {
        "sig_hits": sig_hits,
        "dps_hits": dps_hits,
        "keywords_hits": sorted(set(keywords_hits)),
        "username_hint": mc_user
    }

# ----------------------------
# Main
# ----------------------------

def main():
    print("=== Minecraft SS Tool (Windows) ===\n")
    log_line("=== Minecraft SS Tool (Windows) ===")

    # 1) Find javaw.exe PID (Minecraft)
    javaw_pid = get_pid_by_name("javaw.exe")
    memory_result = {}
    if javaw_pid:
        msg = f"[+] javaw.exe PID: {javaw_pid}"
    else:
        msg = "[!] javaw.exe not found (Minecraft not running?) — skipping memory scan."
    print(msg); log_line(msg)

    # 2) Scan memory (javaw)
    if javaw_pid:
        print("\n[*] Scanning javaw.exe memory for hacked-client signatures..."); log_line("[*] Scanning javaw.exe memory...")
        memory_result = scan_javaw_memory(javaw_pid)
        if memory_result.get("error") == "permission_denied":
            msg = "    [!] Permission denied reading javaw.exe memory."
            print(msg); log_line(msg)
        else:
            if memory_result.get("sig_hits"):
                for sig, label in memory_result["sig_hits"][:50]:
                    msg = f"    [SIG] {label}: '{sig}'"
                    print(f"{RED}{msg}{RESET}"); log_line(msg)
            if memory_result.get("dps_hits"):
                for k, label in memory_result["dps_hits"]:
                    msg = f"    [DPS] {label}: key='{k}'"
                    print(f"{RED}{msg}{RESET}"); log_line(msg)
            if memory_result.get("keywords_hits"):
                msg = f"    [KW] generic cheat keywords found: {', '.join(memory_result['keywords_hits'])}"
                print(f"{RED}{msg}{RESET}"); log_line(msg)
            if memory_result.get("username_hint"):
                msg = f"    [User] Possible username hint: {memory_result['username_hint']}"
                print(msg); log_line(msg)

    # 3) JNativeHook temp DLL check
    print("\n[*] Checking for JNativeHook DLL in Temp..."); log_line("[*] Checking for JNativeHook DLL in Temp...")
    jnh = check_jnativehook()
    if jnh:
        for p in jnh:
            msg = f"    [!] JNativeHook DLL found: {p}"
            print(f"{RED}{msg}{RESET}"); log_line(msg)
    else:
        msg = "    [+] Nothing found"
        print(msg); log_line(msg)

    # 4) Deleted executables observation
    print("\n[*] Looking for recently executed & deleted EXEs..."); log_line("[*] Checking deleted executables...")
    deleted = {}
    deleted_pca, del_err = get_deleted_executables_pca()
    if del_err == "missing_pids":
        msg = "    [!] Could not locate PcaSvc or explorer.exe — skipping PCA method."
        print(msg); log_line(msg)
    elif del_err == "permission_denied":
        msg = "    [!] Permission denied reading system process memory — skipping PCA method."
        print(msg); log_line(msg)
    elif deleted_pca:
        deleted["pca"] = deleted_pca
        for k, v in list(deleted_pca.items())[:50]:
            msg = f"    [DEL][PCA] {k} ({v})"
            print(f"{RED}{msg}{RESET}"); log_line(msg)

    pf_res = scan_prefetch_deleted_exes()
    if pf_res:
        deleted["prefetch"] = pf_res
        print("    [Prefetch] Potentially deleted or bad EXEs:"); log_line("[Prefetch] Potentially deleted/bad EXEs:")
        for exe, status, h in pf_res[:50]:
            if status == "deleted":
                msg = f"       - {exe} [deleted]"
                print(f"{RED}{msg}{RESET}"); log_line(msg)
            elif status == "bad_hash":
                msg = f"       - {exe} [bad hash: {h}]"
                print(f"{RED}{msg}{RESET}"); log_line(msg)

    pf_hash_res = scan_prefetch_hashes()
    if pf_hash_res:
        deleted["prefetch_hash"] = pf_hash_res
        print("    [Prefetch-Hash] Known bad prefetch EXEs:"); log_line("[Prefetch-Hash] Known bad prefetch EXEs:")
        for exe, status, h in pf_hash_res[:50]:
            msg = f"       - {exe} [{status} {h}]"
            print(f"{RED}{msg}{RESET}"); log_line(msg)

    rb_res = scan_recycle_bin_deleted_exes()
    if rb_res:
        deleted["recyclebin"] = rb_res
        print("    [RecycleBin] Deleted/present EXEs:"); log_line("[RecycleBin] Deleted/present EXEs:")
        for f, user, status, h in rb_res[:50]:
            if status in ("deleted", "bad_hash"):
                msg = f"       - {f} (User: {user}) [{status}{' ' + h if h else ''}]"
                print(f"{RED}{msg}{RESET}"); log_line(msg)
            else:
                msg = f"       - {f} (User: {user}) [present]"
                print(msg); log_line(msg)

    # 5) Minecraft mods/jars scanning
    mods, mods_flagged = list_mods_and_flag_illegal()
    if mods_flagged:
        print("\n[!] Suspicious/illegal mods found:"); log_line("[!] Suspicious/illegal mods found:")
        for fp, why in mods_flagged:
            msg = f"    {fp} [{why}]"
            print(f"{RED}{msg}{RESET}"); log_line(msg)

    # 6) Logs
    print("\n[*] Scanning Minecraft logs (joined servers & suspicious markers)..."); log_line("[*] Scanning logs...")
    servers, logs_susp = scan_logs()
    if servers:
        print("    [Servers] Recently seen:"); log_line("[Servers] Recently seen:")
        for s in servers[:20]:
            msg = f"      - {s}"
            print(msg); log_line(msg)
    if logs_susp:
        print(RED + "    [!] Suspicious log markers:" + RESET); log_line("[!] Suspicious log markers:")
        for fp, line in logs_susp[:30]:
            msg = f"      - {os.path.basename(fp)}: {line}"
            print(f"{RED}{msg}{RESET}"); log_line(msg)

    # 7) Recording software
    print("\n[*] Checking for recording/overlay software..."); log_line("[*] Checking recording software...")
    recs = detect_recorders()
    for exe, name in recs:
        msg = f"    [REC] {name} running ({exe})"
        print(msg); log_line(msg)

    # 8) Classification
    findings = {
        "memory": memory_result if memory_result else {},
        "mods_flagged": mods_flagged,
        "logs_suspicious": logs_susp,
        "jnativehook": jnh,
        "deleted_exes": deleted
    }
    verdict, reasons = classify(findings)

    print("\n==================== RESULT ===================="); log_line("==================== RESULT ====================")
    verdict_color = RED if verdict != "CLEAN" else RESET
    msg = f"Conclusion: {verdict}"
    print(f"Conclusion: {verdict_color}{verdict}{RESET}"); log_line(msg)
    if reasons:
        print("Reasons:"); log_line("Reasons:")
        for r in reasons:
            print(f" - {r}"); log_line(f" - {r}")
    else:
        print(" - No notable findings."); log_line(" - No notable findings.")
    print("================================================"); log_line("================================================")

    print(f"\nResults saved to {LOGFILE}"); log_line(f"Results saved to {LOGFILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
