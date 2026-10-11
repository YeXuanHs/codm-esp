#!/usr/bin/env python3
"""
Synthetic IL2CPP global-metadata generator — used to self-test
parse_metadata.py's version-agnostic layout detection without
needing a live game process.

    python mk_test_blob.py test_meta.bin
    python parse_metadata.py test_meta.bin --grep health
"""
import struct
import sys

TYPES = [
    ("CODM.Game", "PlayerEntity",
     ["m_Health", "m_TeamId", "m_Position", "m_Name", "m_IsBot"]),
    ("CODM.Game", "EnemyManager",
     ["m_Entities", "m_LocalPlayer"]),
    ("UnityEngine", "Vector3", ["x", "y", "z"]),
]

# In real metadata a string index is a BYTE offset into the string section.
strblob = b""
stroff = {}


def S(s):
    global strblob
    if s in stroff:
        return stroff[s]
    off = len(strblob)
    stroff[s] = off
    strblob += s.encode() + b"\x00"
    return off


tok = 0x01000001
FIELDS = []
for ns, tn, fns in TYPES:
    pairs = []
    for f in fns:
        pairs.append((S(f), tok))
        tok += 1
    FIELDS.append([S(ns), S(tn), pairs])

field_count = sum(len(t[2]) for t in FIELDS)
method_count = 2 * len(TYPES)

fieldblob = b"".join(struct.pack("<iiI", ni, 0, tk)
                     for t in FIELDS for (ni, tk) in t[2])
methodblob = b"".join(struct.pack("<i", S("Update")) for _ in range(method_count))

STRIDE = 104          # v29-style Il2CppTypeDefinition
FS_OFF, FC_OFF = 48, 84
MS_OFF, MC_OFF = 52, 80

HEADER_FIELDS = [
    ("stringLiteral", b"", 0),
    ("stringLiteralData", b"", 0),
    ("string", strblob, len(strblob)),
    ("events", b"", 0),
    ("properties", b"", 0),
    ("methods", methodblob, method_count),
    ("parameterDefaultValues", b"", 0),
    ("fieldDefaultValues", b"", 0),
    ("fieldAndParameterDefaultValueData", b"", 0),
    ("fieldMarshaledSizes", b"", 0),
    ("parameters", b"", 0),
    ("fields", fieldblob, field_count),
    ("genericParameters", b"", 0),
    ("genericParameterConstraints", b"", 0),
    ("genericContainers", b"", 0),
    ("nestedTypes", b"", 0),
    ("interfaces", b"", 0),
    ("vtableMethods", b"", 0),
    ("interfaceOffsets", b"", 0),
    ("typeDefinitions", bytes(STRIDE * len(TYPES)), len(TYPES)),
    ("images", b"", 1),
    ("assemblies", b"", 1),
    ("fieldRefs", b"", 0),
    ("referencedAssemblies", b"", 0),
    ("attributeData", b"", 0),
    ("attributeDataRange", b"", 0),
    ("unresolvedVirtualCallParameterTypes", b"", 0),
    ("unresolvedVirtualCallParameterRanges", b"", 0),
    ("windowsRuntimeTypeNames", b"", 0),
    ("windowsRuntimeStrings", b"", 0),
    ("exportedTypeDefinitions", b"", 0),
]

hdr_words = 2 + 2 * len(HEADER_FIELDS)
data_start = hdr_words * 4
while data_start % 16:
    data_start += 4

offsets = {}
sections = []
cur = data_start
for name, blob, cnt in HEADER_FIELDS:
    offsets[name] = cur
    sections.append((cur, blob))
    cur += len(blob)
while cur % 0x1000:
    cur += 1

out = bytearray(cur)
struct.pack_into("<Ii", out, 0, 0xFAB11BAF, 29)
for i, (name, blob, cnt) in enumerate(HEADER_FIELDS):
    struct.pack_into("<II", out, (2 + i * 2) * 4, offsets[name], cnt)
for o, blob in sections:
    out[o:o + len(blob)] = blob

td_off = offsets["typeDefinitions"]
fstart = 0
for i, (ns, tn, fns) in enumerate(TYPES):
    p = td_off + i * STRIDE
    struct.pack_into("<ii", out, p, S(tn), S(ns))   # nameIndex, namespaceIndex
    struct.pack_into("<i", out, p + FS_OFF, fstart)
    struct.pack_into("<i", out, p + MS_OFF, i * 2)
    struct.pack_into("<H", out, p + MC_OFF, 2)
    struct.pack_into("<H", out, p + FC_OFF, len(fns))
    fstart += len(fns)

open(sys.argv[1] if len(sys.argv) > 1 else "test_meta.bin", "wb").write(bytes(out))
print("wrote", len(out), "bytes |", len(TYPES), "types |", field_count, "fields")