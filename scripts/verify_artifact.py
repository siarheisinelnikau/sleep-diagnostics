"""Inspect a packaged PE file without loading or executing it."""
import json
import struct
import sys
from pathlib import Path


def inspect(path):
    data = Path(path).read_bytes()
    def u16(offset):
        return struct.unpack_from("<H", data, offset)[0]
    def u32(offset):
        return struct.unpack_from("<I", data, offset)[0]
    assert data[:2] == b"MZ"
    pe = u32(60)
    assert data[pe:pe + 4] == b"PE\0\0"
    assert u16(pe + 4) == 0x8664, "The package currently targets Windows x64"
    optional = pe + 24
    assert u16(optional) == 0x20B
    assert u16(optional + 68) == 2, "A GUI subsystem is required"
    sections = optional + u16(pe + 20)

    def rva(value):
        for index in range(u16(pe + 6)):
            section = sections + index * 40
            start = u32(section + 12)
            if start <= value < start + max(u32(section + 8), u32(section + 16)):
                return u32(section + 20) + value - start
        raise AssertionError("RVA outside the image")

    base = rva(u32(optional + 112 + 16))
    resources = {}

    def directory(offset, keys=()):
        node = base + offset
        count = u16(node + 12) + u16(node + 14)
        assert len(keys) < 5 and count < 1024
        for index in range(count):
            entry = node + 16 + index * 8
            name, target = u32(entry), u32(entry + 4)
            key = name & 0xFFFF
            if name & 0x80000000:
                name_at = base + (name & 0x7FFFFFFF)
                key = data[name_at + 2:name_at + 2 + u16(name_at) * 2].decode("utf-16-le")
            if target & 0x80000000:
                directory(target & 0x7FFFFFFF, keys + (key,))
            else:
                location = base + target
                start, length = rva(u32(location)), u32(location + 4)
                assert length < len(data) and start + length <= len(data)
                resources[keys + (key,)] = data[start:start + length]

    directory(0)
    manifests = [value.decode("utf-8") for key, value in resources.items() if key[0] == 24]
    assert any('level="asInvoker"' in value and "PerMonitorV2" in value for value in manifests)
    assert any("Sleep Diagnostics" in value.decode("utf-16-le", errors="ignore") for key, value in resources.items() if key[0] == 16)
    groups = [value for key, value in resources.items() if key[0] == 14]
    assert len(groups) == 1, "One intended application icon is required"
    group = groups[0]
    count = struct.unpack_from("<H", group, 4)[0]
    variants = []
    for index in range(count):
        entry = group[6 + 14 * index:20 + 14 * index]
        width = entry[0] or 256
        height = entry[1] or 256
        resource_id = struct.unpack_from("<H", entry, 12)[0]
        icon = next(value for key, value in resources.items() if key[0] == 3 and key[1] == resource_id)
        header, actual_width, doubled_height, planes, bits = struct.unpack_from("<IiiHH", icon)
        assert header == 40 and actual_width == width and doubled_height == height * 2 and bits == 32 and planes == 1
        pixels = icon[40:40 + width * height * 4]
        visible = [(x, y) for y in range(height) for x in range(width) if pixels[(y * width + x) * 4 + 3]]
        assert visible and len(visible) < width * height, "Icon must have both artwork and transparency"
        bounds = [min(x for x, _ in visible), min(y for _, y in visible), max(x for x, _ in visible), max(y for _, y in visible)]
        assert bounds[0] > 0 and bounds[1] > 0 and bounds[2] < width - 1 and bounds[3] < height - 1, "Icon is clipped"
        assert bounds[2] - bounds[0] >= width * 0.6, "Icon has excessive empty padding"
        variants.append(width)
    assert set(variants) == {16, 20, 24, 32, 48, 64, 256}
    print(json.dumps({"artifact": str(path), "architecture": "x64", "subsystem": "Windows GUI", "manifest": "asInvoker, PerMonitorV2", "icon_sizes": variants, "executed": False}))


if __name__ == "__main__":
    inspect(sys.argv[1])
