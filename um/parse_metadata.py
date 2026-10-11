#!/usr/bin/env python3
# ============================================================
# IL2CPP global-metadata parser (version tolerant)
#
# Input : the raw blob dumped by scanner.exe
#         (starts at Il2CppGlobalMetadataHeader, magic 0xFAB11BAF)
# Output: types.json  - full type/field database
#         fields.txt  - flat, greppable "Type.field" listing
#         stats.txt   - table sizes + detected layout
#
# Usage:
#   python parse_metadata.py out/metadata_*.bin
#   python parse_metadata.py out/metadata_*.bin --grep enemy
# ============================================================

import json
import os
import struct
import sys
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SANITY = 0xFAB11BAF

# Table order inside the header, starting at (offset,count) pair #2.
# Entries removed in newer metadata versions are simply ignored below.
TABLES_V24 = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes",
    "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes",
    "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions",
    "images", "assemblies", "metadataUsageLists", "metadataUsagePairs",
    "fieldRefs", "referencedAssemblies", "attributeData",
    "attributeDataRange", "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames",
    "windowsRuntimeStrings", "exportedTypeDefinitions",
]

# Tables that were dropped after metadata v24 (v25+ removed metadataUsage*).
TABLES_V27 = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes",
    "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes",
    "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions",
    "images", "assemblies", "fieldRefs", "referencedAssemblies",
    "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames",
    "windowsRuntimeStrings", "exportedTypeDefinitions",
]


class Meta:
    def __init__(self, blob: bytes):
        if len(blob) < 0x100:
            raise ValueError("blob too small")
        self.blob = blob
        self.sanity, self.version = struct.unpack_from("<Ii", blob, 0)
        if self.sanity != SANITY:
            raise ValueError(f"bad sanity 0x{self.sanity:08X}")
        self.tables = self._parse_tables()

    def _parse_tables(self):
        names = TABLES_V24 if self.version <= 24 else TABLES_V27
        out = {}
        for i, name in enumerate(names):
            off_i = 2 + i * 2
            if (off_i + 1) * 4 + 4 > len(self.blob):
                break
            offset, count = struct.unpack_from("<II", self.blob, off_i * 4)
            if offset > len(self.blob) or count > 0x2000000:
                break
            out[name] = (offset, count)
        return out

    # ---------------- accessors ----------------
    def table_size(self, name):
        off, cnt = self.tables.get(name, (0, 0))
        return cnt

    def string_at(self, index):
        off, _ = self.tables["string"]
        p = off + index
        if p >= len(self.blob):
            return None
        end = self.blob.find(b"\x00", p)
        if end < 0:
            end = len(self.blob)
        return self.blob[p:end].decode("utf-8", "replace")

    def field_defs(self):
        """Yield (nameIndex, typeIndex, token) for every field definition."""
        off, cnt = self.tables.get("fields", (0, 0))
        for i in range(cnt):
            p = off + i * 12
            if p + 12 > len(self.blob):
                break
            ni, ti, tok = struct.unpack_from("<iiI", self.blob, p)
            yield i, ni, ti, tok

    def method_names(self):
        """Return list of method names (nameIndex based)."""
        off, cnt = self.tables.get("methods", (0, 0))
        names = []
        # method definition nameIndex is always the first int32
        for i in range(cnt):
            p = off + i * 4
            if p + 4 > len(self.blob):
                break
            (ni,) = struct.unpack_from("<i", self.blob, p)
            names.append(ni)
        return names


def detect_layout(meta: Meta):
    """
    Work out where fieldStart / methodStart / field_count / method_count live
    inside Il2CppTypeDefinition, without hardcoding a version.

    Invariants used:
      * sum(type.field_count) == fieldsCount
      * fieldStart[i] == fieldStart[i-1] + field_count[i-1]  (contiguous)
    """
    off, cnt = meta.tables.get("typeDefinitions", (0, 0))
    if cnt == 0:
        raise ValueError("no typeDefinitions table")

    # Offsets of populated tables that start after this one — the gap to the
    # first of them tells us roughly how big a typeDefinition record is.
    starts = sorted(o for (o, c) in meta.tables.values() if c > 0 and o > off)

    fields_count = meta.table_size("fields")
    methods_count = meta.table_size("methods")
    str_count = meta.table_size("string")

    # ---- stride candidate set, ordered by likelihood --------------------
    candidates = []
    if starts:
        gap = starts[0] - off
        if gap > 0 and cnt > 0 and gap % cnt == 0:
            candidates.append(gap // cnt)
    # layouts seen in the wild (metadata v24 .. v31)
    candidates += [104, 88, 96, 120, 112, 64, 72, 80, 128]
    if starts:
        base = (starts[0] - off) // cnt if cnt else 0
        for d in range(-8, 9, 4):
            candidates.append(base + d)
    candidates += list(range(32, 0x180, 4))

    seen = set()

    def columns_ok(stride):
        """Cheap validity: every record must have plausible name indexes."""
        if off + cnt * stride > len(meta.blob):
            return False
        for i in range(cnt):
            p = off + i * stride
            n, ns = struct.unpack_from("<ii", meta.blob, p)
            if str_count:
                if not (0 <= n < str_count and 0 <= ns < str_count):
                    return False
            else:
                if not (0 <= n < 0x4000000 and 0 <= ns < 0x4000000):
                    return False
        return True

    def find_columns(stride):
        """Locate the uint16 count columns and the int32 start columns."""
        records = [meta.blob[off + i * stride: off + (i + 1) * stride]
                   for i in range(cnt)]

        def sum_u16(o):
            tot = 0
            for r in records:
                if o + 2 > len(r):
                    return None
                tot += struct.unpack_from("<H", r, o)[0]
            return tot

        # In every Il2CppTypeDefinition the eight counts are stored as a
        # contiguous run of uint16:
        #   method, property, field, event, nested, vtable, interfaces, iface_off
        # So field_count sits at run_start+4 and method_count at run_start.
        # Requiring that adjacency kills the false positives you get from
        # matching a lone uint16 column by coincidence.
        run = None
        for o in range(8, stride - 15, 2):
            if fields_count and sum_u16(o + 4) == fields_count and \
               sum_u16(o) == methods_count:
                run = o
                break

        if run is not None:
            mc = [run]
            fc = [run + 4]
        else:
            fc = [o for o in range(8, stride - 1, 2)
                  if fields_count > 0 and sum_u16(o) == fields_count]
            mc = [o for o in range(8, stride - 1, 2)
                  if methods_count > 0 and sum_u16(o) == methods_count]

        def find_start(count_off, total):
            best = None
            for o in range(8, stride - 3, 4):
                vals = [struct.unpack_from("<i", r, o)[0] for r in records
                        if o + 4 <= len(r)]
                if len(vals) != len(records) or not vals:
                    continue
                if vals[0] < 0 or vals[-1] < 0 or vals[-1] > total:
                    continue
                cur = vals[0]
                ok = True
                for i in range(1, len(vals)):
                    if vals[i] < cur:
                        ok = False
                        break
                    cur = vals[i] + struct.unpack_from("<H", records[i], count_off)[0]
                if ok:
                    score = (1 if vals[-1] == total else 0) * 1000 + (1 if vals[0] == 0 else 0)
                    if best is None or score > best[1]:
                        best = (o, score)
            return best[0] if best else None

        return {
            "field_count_off": fc[0] if fc else None,
            "method_count_off": mc[0] if mc else None,
            "field_start_off": find_start(fc[0], fields_count) if fc else None,
            "method_start_off": find_start(mc[0], methods_count) if mc else None,
        }

    best_stride = None
    best_cols = None
    for s in candidates:
        if s in seen or s < 16 or s > 512:
            continue
        seen.add(s)
        if not columns_ok(s):
            continue
        cols = find_columns(s)
        # prefer a stride where we actually located the field columns
        if cols["field_count_off"] is not None and cols["field_start_off"] is not None:
            best_stride, best_cols = s, cols
            break
        if best_stride is None:
            best_stride, best_cols = s, cols

    if best_stride is None:
        raise ValueError("no plausible typeDefinitions stride")

    layout = {"stride": best_stride, "count": cnt}
    layout.update(best_cols)
    return layout


def parse(blob: bytes):
    meta = Meta(blob)
    layout = detect_layout(meta)

    # field definition table -> {index: (name, typeIndex, token)}
    fields = {}
    for i, ni, ti, tok in meta.field_defs():
        fields[i] = (meta.string_at(ni), ti, tok)

    types = []
    off = meta.tables["typeDefinitions"][0]
    stride, cnt = layout["stride"], layout["count"]

    fs_off = layout["field_start_off"]
    fc_off = layout["field_count_off"]
    ms_off = layout["method_start_off"]
    mc_off = layout["method_count_off"]

    for i in range(cnt):
        p = off + i * stride
        rec = meta.blob[p:p + stride]
        if len(rec) < 12:
            break
        name_idx, ns_idx = struct.unpack_from("<ii", rec, 0)
        name = meta.string_at(name_idx) or ""
        ns = meta.string_at(ns_idx) or ""

        flist = []
        if fs_off is not None and fc_off is not None:
            fstart = struct.unpack_from("<i", rec, fs_off)[0]
            fcount = struct.unpack_from("<H", rec, fc_off)[0]
            for k in range(fcount):
                fi = fstart + k
                if fi in fields:
                    fname, tidx, tok = fields[fi]
                    flist.append({"name": fname, "typeIndex": tidx, "token": tok})

        mcount = 0
        if mc_off is not None:
            mcount = struct.unpack_from("<H", rec, mc_off)[0]

        types.append({
            "index": i,
            "namespace": ns,
            "name": name,
            "fullName": f"{ns}.{name}" if ns else name,
            "fieldCount": len(flist),
            "methodCount": mcount,
            "fields": flist,
        })

    return meta, layout, types


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    path = sys.argv[1]
    grep = None
    if "--grep" in sys.argv:
        grep = sys.argv[sys.argv.index("--grep") + 1].lower()

    blob = open(path, "rb").read()
    try:
        meta, layout, types = parse(blob)
    except Exception as e:
        print(f"[!] parse failed: {e}")
        return 2

    base = os.path.splitext(path)[0]

    with open(base + "_types.json", "w", encoding="utf-8") as f:
        json.dump({"version": meta.version,
                   "layout": layout,
                   "tables": {k: list(v) for k, v in meta.tables.items()},
                   "types": types}, f, ensure_ascii=False, indent=1)

    with open(base + "_fields.txt", "w", encoding="utf-8") as f:
        for t in types:
            for fl in t["fields"]:
                f.write(f"{t['fullName']}.{fl['name']}\t"
                        f"typeIndex={fl['typeIndex']}\ttoken=0x{fl['token']:08X}\n")

    with open(base + "_stats.txt", "w", encoding="utf-8") as f:
        f.write(f"blob        : {path} ({len(blob)} bytes)\n")
        f.write(f"sanity      : 0x{meta.sanity:08X}\n")
        f.write(f"version     : {meta.version}\n")
        f.write(f"layout      : {layout}\n")
        f.write(f"types       : {len(types)}\n")
        for k, (o, c) in sorted(meta.tables.items(), key=lambda kv: kv[1][0]):
            f.write(f"  table {k:40s} off=0x{o:08X} count={c}\n")

    print(f"[+] metadata v{meta.version}: {len(types)} types")
    print(f"[+] layout: {layout}")
    print(f"[+] {base}_types.json / _fields.txt / _stats.txt")

    if grep:
        print(f"\n=== matches for '{grep}' ===")
        for t in types:
            full = t["fullName"].lower()
            hit = grep in full
            shown = []
            for fl in t["fields"]:
                if grep in (fl["name"] or "").lower():
                    hit = True
                    shown.append(fl)
            if hit:
                print(f"\n{t['fullName']}  (fields={t['fieldCount']}, methods={t['methodCount']})")
                if full.count(grep) and not shown:
                    print("    <type name match>")
                for fl in shown[:40]:
                    print(f"    {fl['name']}   typeIndex={fl['typeIndex']} "
                          f"token=0x{fl['token']:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())