#!/usr/bin/env python3
"""Re-derive the whole PlayerInfo read chain for the CURRENT match.

  metadata -> PlayerInfo class -> field-info table -> instance -> values

Nothing is hardcoded except the two constants baked into the metadata layout:
the string-table offset (2797508) and its size (9758944).
"""
import json
import os
import re
import struct
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SC = "./scanner.exe"
PID = sys.argv[1] if len(sys.argv) > 1 else "21648"
STRO, STRSZ = 0x2AAFC4, 9758944


def run(*a):
    return subprocess.run([SC] + list(a), capture_output=True, text=True,
                         errors="replace").stdout


def step(msg):
    print("\n== " + msg, flush=True)


# ---------- 1. metadata base ----------
step("1/7 定位 IL2CPP 元数据")
out = run("meta", "--pid", PID)
m = re.search(r"HIT\s+([0-9A-F]+)\s+il2cpp-global-metadata", out)
if not m:
    print("!! 未找到元数据"); sys.exit(1)
MBASE = int(m.group(1), 16)
STR = MBASE + STRO
print(f"   元数据 0x{MBASE:X}   字符串表 0x{STR:X}..0x{STR+STRSZ:X}")

# ---------- 2. PlayerInfo name VA ----------
step("2/7 由元数据算 PlayerInfo 类名 VA")
blob = f"out/metadata_{PID}_{MBASE:016X}.bin"
b = open(blob, "rb").read()
TD, STRIDE, N = 49247884, 80, 4228480 // 80


def s(x):
    if not (0 <= x < STRSZ):
        return None
    e = b.find(b"\x00", STRO + x)
    return b[STRO + x:e].decode("utf-8", "replace")


NAMEVA = None
for i in range(N):
    ni, nsi = struct.unpack_from("<ii", b, TD + i * STRIDE)
    if s(ni) == "PlayerInfo" and s(nsi) == "GameEngine":
        NAMEVA = STR + ni
        break
print(f"   PlayerInfo nameVA = 0x{NAMEVA:X}")

# ---------- 3. class address ----------
step("3/7 定位 Il2CppClass")
out = run("findptr", f"{NAMEVA:X}", "--pid", PID)
CLS = None
for h in re.findall(r"PTR HIT ([0-9A-F]+)", out):
    a = int(h, 16)
    # Il2CppClass: +0x00 image, +0x08 gc_desc, +0x10 name, +0x18 namespace
    r = run("read", f"{a - 0x10:X}", "0x20", "--pid", PID)
    raw = b""
    for ln in r.splitlines():
        mm = re.match(r"^([0-9A-F]+)\s+((?:[0-9A-F]{2} )+)", ln.strip())
        if mm:
            raw += bytes.fromhex(mm.group(2).replace(" ", ""))
    if len(raw) < 0x20:
        continue
    q = struct.unpack("<QQQQ", raw)
    if q[2] == NAMEVA:
        CLS = a - 0x10
        break
if not CLS:
    print("!! 未定位类"); sys.exit(1)
print(f"   PlayerInfo class = 0x{CLS:X}")

# ---------- 4. field-info table ----------
step("4/7 扫描字段信息表（可能要扫全堆）")
run("fieldtable", f"{CLS:X}", f"{STR:X}", str(STRSZ), "--pid", PID)
if not os.path.exists("fieldtable.bin"):
    print("!! 未找到字段表"); sys.exit(1)
fb = open("fieldtable.bin", "rb").read()
# the dump is a raw address span; keep only real records
recs = []
for o in range(0, len(fb) - 32, 32):
    if struct.unpack_from("<Q", fb, o)[0] == CLS:
        recs.append((struct.unpack_from("<I", fb, o + 8)[0],
                     struct.unpack_from("<Q", fb, o + 16)[0]))
print(f"   {len(recs)} 条记录")

# ---------- 5. read names + align ----------
step("5/7 读字段名并与元数据对齐")
rt = []
for _, ptr in recs:
    r = run("read", f"{ptr:X}", "0x90", "--pid", PID)
    raw = b""
    for ln in r.splitlines():
        mm = re.match(r"^([0-9A-F]+)\s+((?:[0-9A-F]{2} )+)", ln.strip())
        if mm:
            raw += bytes.fromhex(mm.group(2).replace(" ", ""))
    e = raw.find(b"\x00")
    rt.append(raw[:e if e >= 0 else len(raw)].decode("utf-8", "replace"))
print(f"   读到 {sum(1 for x in rt if x)} 个名字")

d = json.load(open("out/metadata_2304_000000002A2B0040_types.json", encoding="utf-8"))
md = [f["name"] for f in
      [t for t in d["types"] if t["fullName"] == "GameEngine.PlayerInfo"][0]["fields"]]
best = (0, 0)
for sh in range(-8, 9):
    hit = sum(1 for i, n in enumerate(rt) if 0 <= i + sh < len(md) and n == md[i + sh])
    if hit > best[1]:
        best = (sh, hit)
SH = best[0]
print(f"   最佳 shift = {SH:+d}  命中 {best[1]}/{len(rt)}")
if best[1] < len(rt) * 0.9:
    print("!! 对齐失败"); sys.exit(1)

fmap = [{"offset": recs[i][0], "name": md[i + SH], "metaIndex": i + SH}
        for i in range(len(recs)) if 0 <= i + SH < len(md)]
json.dump(fmap, open("PI_FIELD_OFFSETS.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=0)
print(f"   已保存 PI_FIELD_OFFSETS.json ({len(fmap)} 条)")

# ---------- 6. instance ----------
step("6/7 找 PlayerInfo 实例")
out = run("findptr", f"{CLS:X}", "--pid", PID)
hits = sorted({int(x, 16) for x in re.findall(r"PTR HIT ([0-9A-F]+)", out)})
hits = [a for a in hits if 0x30000000 <= a < 0x50000000]
os.makedirs("ii", exist_ok=True)
best = None
for a in hits:
    if not os.path.exists(f"ii/{a:X}.bin"):
        run("dump", f"{a:X}", "0x6D8", f"ii/{a:X}.bin", "--pid", PID)
    try:
        d2 = open(f"ii/{a:X}.bin", "rb").read()
    except OSError:
        continue
    if len(d2) != 0x6D8 or struct.unpack_from("<Q", d2, 0)[0] != CLS:
        continue
    n = len(d2) // 8
    q = struct.unpack_from(f"<{n}Q", d2, 0)
    p = sum(1 for v in q[1:] if 0x10000 < v < 0x7FFFFFFF00000000)
    if best is None or p > best[0]:
        best = (p, a, d2)
if not best:
    print("!! 未找到实例"); sys.exit(1)
print(f"   实例 0x{best[1]:X}  堆指针 {best[0]}/218")

# ---------- 7. read values ----------
step("7/7 读取关键字段")
inst = best[2]
names = {e["offset"]: e["name"] for e in fmap}
KEY = ["m_IsPlayerDead", "m_PlayerID", "m_TeamID", "m_TeamSeatID",
       "m_NickName", "m_GamePlayerId", "HealthSequence",
       "m_KineticArmorHP", "m_KineticArmorMaxHP", "m_PerArmorPlateHealth"]
byname = {e["name"]: e["offset"] for e in fmap}
for nm in KEY:
    if nm not in byname:
        print(f"   {nm:22s} 不在字段表中"); continue
    off = byname[nm]
    if off + 8 > len(inst):
        continue
    q = struct.unpack_from("<Q", inst, off)[0]
    i = struct.unpack_from("<i", inst, off)[0]
    print(f"   {nm:22s} @0x{off:03X}  i32={i:<12d} q64=0x{q:016X}")
