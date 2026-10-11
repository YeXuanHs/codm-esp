#!/usr/bin/env python3
# ============================================================
# IL2CPP global-metadata parser (version tolerant, size-based header)
#
# Works on the raw blob dumped by scanner.exe, which starts at
# Il2CppGlobalMetadataHeader (magic 0xFAB11BAF).
#
# Key design point: in this header every second word is a BYTE SIZE, not an
# element count. Element counts are recovered by dividing by the struct size
# of each table. Nothing about the metadata *version* is hardcoded - the
# Il2CppTypeDefinition record stride and the position of its columns are
# derived from structural invariants instead:
#
#   * every record's nameIndex / namespaceIndex falls inside the string table
#   * sum(type.field_count) == number of field definitions
#   * the eight counts are a contiguous run of uint16:
#       method, property, field, event, nested, vtable, interfaces, iface_off
#   * fieldStart[i] == fieldStart[i-1] + field_count[i-1]   (fields are packed)
#
# Usage:
#   python parse_metadata.py out/metadata_*.bin
#   python parse_metadata.py out/metadata_*.bin --grep enemy
# ============================================================

import json
import os
import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SANITY = 0xFAB11BAF

# Table order in the header. Tables removed in later versions keep their
# (0,0) entry; every value is validated against the blob size before use.
TABLES = [
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

# Struct sizes that are stable across versions.
ELEM = {
    "stringLiteral": 8,      # {length, dataIndex}
    "fields": 12,            # {nameIndex, typeIndex, token}
    "fieldRefs": 8,
    "genericParameters": 16,
    "images": 40,
    "assemblies": 64,
    "referencedAssemblies": 40,
    "interfaceOffsets": 4,
    "nestedTypes": 4,
    "events": 16,
}


class Meta:
    def __init__(self, blob: bytes):
        if len(blob) < 0x100:
            raise ValueError("blob too small")
        self.blob = blob
        self.sanity, self.version = struct.unpack_from("<Ii", blob, 0)
        if self.sanity != SANITY:
            raise ValueError(f"bad sanity 0x{self.sanity:08X}")
        self.tables = {}
        for i, name in enumerate(TABLES):
            off_i = 2 + i * 2
            if (off_i + 1) * 4 + 4 > len(blob):
                break
            off, size = struct.unpack_from("<II", blob, off_i * 4)
            if off and (off >= len(blob) or off + size > len(blob)):
                off = size = 0
            self.tables[name] = (off, size)

    def off(self, name):
        return self.tables.get(name, (0, 0))[0]

    def size(self, name):
        return self.tables.get(name, (0, 0))[1]

    def count(self, name):
        elem = ELEM.get(name)
        return self.size(name) // elem if elem else 0

    def string_at(self, index):
        base = self.off("string")
        p = base + index
        if base == 0 or index < 0 or p >= len(self.blob):
            return None
        end = self.blob.find(b"\x00", p)
        if end < 0:
            end = len(self.blob)
        return self.blob[p:end].decode("utf-8", "replace")

    def field_defs(self, elem=None, total=None):
        """Yield (index, nameIndex, typeIndex) for the fields table."""
        base, size = self.tables.get("fields", (0, 0))
        elem = elem or ELEM["fields"]
        n = total if total else count_of(size, elem)
        str_size = self.size("string")
        for i in range(n):
            p = base + i * elem
            if p + 8 > len(self.blob):
                break
            ni, ti = struct.unpack_from("<ii", self.blob, p)
            yield i, ni, ti


def detect_field_elem(meta: Meta, fields_total: int):
    """
    The Il2CppFieldDefinition record is not a fixed size across builds
    (CODM ships a 10-byte variant where stock IL2CPP uses 12), so pick the
    stride whose every nameIndex lands inside the string table and whose
    element count matches the field count summed from the type definitions.
    """
    base = meta.off("fields")
    str_size = meta.size("string")
    for elem in (12, 10, 16, 8, 4, 6):
        if fields_total and meta.size("fields") < fields_total * elem:
            continue
        ok = True
        for i in range(fields_total):
            ni = struct.unpack_from("<i", meta.blob, base + i * elem)[0]
            if not (0 <= ni < str_size):
                ok = False
                break
        if ok:
            return elem
    raise ValueError("cannot determine the field definition stride")


def count_of(size, elem):
    return size // elem if elem else 0


def detect_layout(meta: Meta):
    td_off = meta.off("typeDefinitions")
    td_size = meta.size("typeDefinitions")
    str_size = meta.size("string")
    if td_off == 0 or td_size == 0:
        raise ValueError("no typeDefinitions table")
    if str_size == 0:
        raise ValueError("no string table")

    # ---- stride: a divisor of the table size whose records all carry
    #      in-range name indexes. Prefer the sizes seen in the wild.
    divisors = [d for d in range(32, 0x101, 4) if td_size % d == 0]
    preferred = [88, 96, 104, 80, 76, 72, 84, 100, 112, 120, 64, 128]
    ordered = preferred + [d for d in divisors if d not in preferred]

    stride = types = None
    for s in ordered:
        if s not in divisors:
            continue
        n = td_size // s
        ok = True
        for i in range(n):
            ni, nsi = struct.unpack_from("<ii", meta.blob, td_off + i * s)
            if not (0 <= ni < str_size and 0 <= nsi < str_size):
                ok = False
                break
        if ok:
            stride, types = s, n
            break
    if stride is None:
        raise ValueError("no valid typeDefinitions stride")

    records = [meta.blob[td_off + i * stride: td_off + (i + 1) * stride]
               for i in range(types)]

    def sum_u16(o):
        if o + 2 > stride:
            return None
        return sum(struct.unpack_from("<H", r, o)[0] for r in records)

    # ---- locate the contiguous run of eight uint16 counts.
    #      Canonical order: method, property, field, event, nested,
    #                      vtable, interfaces, interface_offsets.
    #      Several of those totals are independently known from table
    #      sizes / struct sizes, so anchor on as many as possible.
    anchors = [
        (2, meta.size("properties") // 12),   # property_count
        (3, meta.size("events") // 16),        # event_count
        (4, meta.size("nestedTypes") // 4),    # nested_type_count
        (6, meta.size("interfaces") // 4),     # interfaces_count
    ]
    anchors = [(k, v) for k, v in anchors if v > 0]

    run, run_score = None, 0
    for o in range(8, stride - 15, 2):
        score = sum(1 for k, v in anchors if sum_u16(o + 2 * k) == v)
        if score > run_score:
            run, run_score = o, score
    if run is None or run_score < 2:
        raise ValueError(f"cannot locate the count run (best score {run_score})")

    method_count_off = run
    field_count_off = run + 4
    fields_total = sum_u16(field_count_off)
    methods_total = sum_u16(method_count_off)
    msize = meta.size("methods")
    method_elem = msize // methods_total if methods_total and msize % methods_total == 0 else 0

    # ---- fieldStart: an int32 column whose running cursor (incremented by
    #      each type's field_count) walks the whole fields table exactly.
    #      Types with no fields may carry -1 as a sentinel.
    field_counts = [struct.unpack_from("<H", r, field_count_off)[0] for r in records]
    field_start_off = None
    for o in range(4, field_count_off - 3):
        col = [struct.unpack_from("<i", r, o)[0] if o + 4 <= len(r) else -2
               for r in records]
        if col[0] not in (0, -1) or (col[0] == -1 and field_counts[0]):
            continue
        cur, ok, bad = 0, True, 0
        for i, fc in enumerate(field_counts):
            v = col[i]
            if v == -1:
                if fc:                       # sentinel only valid for empty types
                    bad += 1
                continue
            if v != cur:
                bad += 1
                if bad > 4:
                    ok = False
                    break
            cur = v + fc
        if ok and cur == fields_total:
            field_start_off = o
            break
    if field_start_off is None:
        raise ValueError("cannot locate the fieldStart column")

    return {
        "stride": stride,
        "types": types,
        "count_run": run,
        "field_start_off": field_start_off,
        "field_count_off": field_count_off,
        "method_start_off": None,
        "method_count_off": method_count_off,
        "method_elem": method_elem,
        "fields_total": fields_total,
        "methods_total": methods_total,
    }


def parse(blob: bytes):
    meta = Meta(blob)
    layout = detect_layout(meta)
    field_elem = detect_field_elem(meta, layout["fields_total"])
    layout["field_elem"] = field_elem

    fields = {}
    for i, ni, ti in meta.field_defs(field_elem, layout["fields_total"]):
        fields[i] = (meta.string_at(ni), ti)

    td_off = meta.off("typeDefinitions")
    stride = layout["stride"]
    fs_off = layout["field_start_off"]
    fc_off = layout["field_count_off"]
    mc_off = layout["method_count_off"]

    types = []
    for i in range(layout["types"]):
        rec = meta.blob[td_off + i * stride: td_off + (i + 1) * stride]
        if len(rec) < 12:
            break
        name_idx, ns_idx = struct.unpack_from("<ii", rec, 0)
        name = meta.string_at(name_idx) or ""
        ns = meta.string_at(ns_idx) or ""

        flist = []
        fstart = struct.unpack_from("<i", rec, fs_off)[0]
        fcount = struct.unpack_from("<H", rec, fc_off)[0]
        if fcount and fstart >= 0:
            for k in range(fcount):
                fi = fstart + k
                if fi in fields:
                    fname, tidx = fields[fi]
                    flist.append({"name": fname, "typeIndex": tidx})

        types.append({
            "index": i,
            "namespace": ns,
            "name": name,
            "fullName": f"{ns}.{name}" if ns else name,
            "fieldCount": len(flist),
            "methodCount": struct.unpack_from("<H", rec, mc_off)[0] if mc_off is not None else 0,
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
        json.dump({"version": meta.version, "layout": layout,
                   "tables": {k: list(v) for k, v in meta.tables.items()},
                   "types": types}, f, ensure_ascii=False)

    with open(base + "_fields.txt", "w", encoding="utf-8") as f:
        for t in types:
            for fl in t["fields"]:
                f.write(f"{t['fullName']}.{fl['name']}\t"
                        f"typeIndex={fl['typeIndex']}\n")

    with open(base + "_stats.txt", "w", encoding="utf-8") as f:
        f.write(f"blob      : {path} ({len(blob)} bytes)\n")
        f.write(f"sanity    : 0x{meta.sanity:08X}\n")
        f.write(f"version   : {meta.version}\n")
        f.write(f"layout    : {layout}\n")
        f.write(f"types     : {len(types)}\n")
        for k in TABLES:
            o, s = meta.tables.get(k, (0, 0))
            f.write(f"  {k:40s} off=0x{o:08X} size={s} count={meta.count(k)}\n")

    print(f"[+] metadata v{meta.version}: {len(types)} types")
    print(f"[+] layout: {layout}")

    if grep:
        hits = 0
        for t in types:
            shown = [fl for fl in t["fields"]
                     if grep in (fl["name"] or "").lower()]
            if not (shown or grep in t["fullName"].lower()):
                continue
            hits += 1
            print(f"\n{t['fullName']}  (fields={t['fieldCount']}, "
                  f"methods={t['methodCount']})")
            for fl in shown[:60]:
                print(f"    {fl['name']}   typeIndex={fl['typeIndex']}")
        print(f"\n[=] {hits} matching types")
    return 0


if __name__ == "__main__":
    sys.exit(main())