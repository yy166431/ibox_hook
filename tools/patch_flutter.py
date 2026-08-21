#!/usr/bin/env python3
"""
静态 patch Flutter.framework/Flutter:
  RVA 0x481ca8  BLR X8 (D63F0100)  ->  BRK #0xCA8 (D4219500)

iOS 26 轻松签场景下 runtime inline hook 会触发 CODESIGNING/Invalid Page。
必须离线改二进制，dylib 只注册 EXC_BREAKPOINT 处理，模拟 BLR X8。

用法:
  python patch_flutter.py <Flutter二进制路径> [-o 输出路径]
  默认原地旁路写 Flutter.patched，验证通过后你自己替换进 IPA。
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import sys
from pathlib import Path

RVA = 0x481CA8
ORIG = 0xD63F0100  # BLR X8
# BRK #imm16 : 0xD4200000 | (imm16 << 5)
BRK_IMM = 0x0CA8
PATCH = 0xD4200000 | (BRK_IMM << 5)  # 0xD4219500


def md5(p: Path) -> str:
    h = hashlib.md5()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def patch(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())
    if len(data) < RVA + 4:
        raise SystemExit(f"文件太小: {len(data)}")

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        raise SystemExit(f"不是 arm64 Mach-O: magic={magic:#x}")

    cur = struct.unpack_from("<I", data, RVA)[0]
    if cur == PATCH:
        print(f"[*] 已经 patch 过: {src} @ {RVA:#x} = {cur:#x}")
        if src.resolve() != dst.resolve():
            shutil.copy2(src, dst)
            print(f"[*] 已复制到 {dst}")
        return

    if cur != ORIG:
        # dump 附近帮助定位
        print(f"[!] 期望 {ORIG:#x} (BLR X8), 实际 {cur:#x}")
        for d in range(-16, 20, 4):
            off = RVA + d
            if 0 <= off + 4 <= len(data):
                w = struct.unpack_from("<I", data, off)[0]
                print(f"    {off:#x}: {w:#010x}")
        raise SystemExit("偏移/版本不匹配，拒绝 patch（别拿错 Flutter）")

    data[RVA : RVA + 4] = struct.pack("<I", PATCH)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)

    verify = struct.unpack_from("<I", dst.read_bytes(), RVA)[0]
    print(f"[+] OK {src.name}")
    print(f"    RVA  {RVA:#x}")
    print(f"    was  {ORIG:#x}  BLR X8")
    print(f"    now  {verify:#x}  BRK #{BRK_IMM:#x}")
    print(f"    md5  {md5(src)} -> {md5(dst)}")
    print(f"    out  {dst} ({dst.stat().st_size} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Patch Flutter addText BLR->BRK")
    ap.add_argument("flutter", type=Path, help="Flutter.framework/Flutter 路径")
    ap.add_argument("-o", "--output", type=Path, default=None, help="输出路径")
    ap.add_argument("--in-place", action="store_true", help="原地覆盖（危险，先备份）")
    args = ap.parse_args()

    src: Path = args.flutter
    if not src.is_file():
        raise SystemExit(f"找不到: {src}")

    if args.in_place:
        bak = src.with_suffix(src.suffix + ".bak")
        if not bak.exists():
            shutil.copy2(src, bak)
            print(f"[*] 备份 -> {bak}")
        dst = src
    else:
        dst = args.output or src.with_name(src.name + ".patched")

    patch(src, dst)


if __name__ == "__main__":
    main()
