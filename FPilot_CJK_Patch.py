#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import os
import re
import struct
import sys
import uuid
from pathlib import Path

TITLE = "File Pilot 中文 / 韩文 / 常用符号补丁"

# ============================================================
# 原始 File Pilot 范围表签名
# 17 个 Unicode range
# 每个 range：start uint32 + end uint32 = 8 字节
# 总长度：17 * 8 = 136 字节
# ============================================================
ORIGINAL_RANGES = [
    (0x0020, 0x007F),  # Basic Latin
    (0x0080, 0x00FF),  # Latin-1 Supplement
    (0x0100, 0x017F),  # Latin Extended-A
    (0x0180, 0x024F),  # Latin Extended-B
    (0x0370, 0x03FF),  # Greek
    (0x0400, 0x04FF),  # Cyrillic
    (0x0500, 0x052F),  # Cyrillic Supplement
    (0x2DE0, 0x2DFF),  # Cyrillic Extended-A
    (0xA640, 0xA69F),  # Cyrillic Extended-B
    (0x1C80, 0x1C8F),  # Cyrillic Extended-C
    (0x0300, 0x036F),  # Combining Diacritical Marks
    (0x2000, 0x206F),  # General Punctuation
    (0x2190, 0x2193),  # Arrows
    (0xE000, 0xE096),  # Private Use Area
    (0xE400, 0xE400),  # Private Use Area
    (0xE800, 0xE801),  # Private Use Area
    (0xEC00, 0xEC00),  # Private Use Area
]

# ============================================================
# 最新补丁范围
#
# 从原始范围表索引 2 开始替换。
# 索引 2 到索引 12，共 11 个 range。
#
# 包含：
#   2E80-33FF   CJK 部首 / 中文标点 / 假名 / 注音 / 韩文兼容字母等
#   3400-4DBF   CJK Extension A
#   4E00-9FFF   CJK 统一汉字主区
#   AC00-D7AF   韩文音节 Hangul Syllables
#   F900-FAFF   CJK 兼容汉字
#   2000-27BF   常用符号，包含 △、箭头、数学符号、几何图形、杂项符号等
#   FF00-FFEF   全角 / 半角形式，包含全角数字、全角标点等
# ============================================================
FIRST_RANGE_INDEX = 2

REPLACEMENT_RANGES = [
    (0x2E80, 0x33FF),  # CJK 标点 / 部首 / 假名 / 注音 / 韩文兼容字母等
    (0x4E00, 0x5FFF),  # CJK 主区
    (0x6000, 0x6FFF),  # CJK 主区
    (0x7000, 0x7FFF),  # CJK 主区
    (0x8000, 0x8FFF),  # CJK 主区
    (0x9000, 0x9FFF),  # CJK 主区
    (0xAC00, 0xBBFF),  # 韩文音节第一段
    (0xBC00, 0xCBFF),  # 韩文音节第二段
    (0xCC00, 0xD7AF),  # 韩文音节第三段
    (0x2000, 0x27BF),  # 常用符号，包含 △
    (0xFF00, 0xFFEF),  # 全角 / 半角
]


def log(text=""):
    try:
        print(text)
    except Exception:
        pass


def show_message(text, title=TITLE, is_error=False, use_gui=False):
    log(text)

    # 如果没有控制台，或者显式要求弹窗，则尝试使用 tkinter 弹窗
    if use_gui or sys.stdout is None:
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()

            try:
                root.attributes("-topmost", True)
            except Exception:
                pass

            if is_error:
                messagebox.showerror(title, text)
            else:
                messagebox.showinfo(title, text)

            root.destroy()
        except Exception:
            pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest().upper()


def ranges_to_bytes(ranges):
    out = bytearray()

    for start, end in ranges:
        if start < 0 or end < 0 or start > end or end > 0x10FFFF:
            raise ValueError(f"无效 Unicode 范围：{start:04X}-{end:04X}")

        out.extend(struct.pack("<II", start, end))

    return bytes(out)


def parse_pe_sections(data):
    if len(data) < 512 or data[0:2] != b"MZ":
        raise ValueError("所选文件不是有效的 PE 可执行文件。")

    pe_offset = struct.unpack_from("<i", data, 0x3C)[0]

    if pe_offset <= 0 or pe_offset + 26 >= len(data):
        raise ValueError("PE 头偏移无效。")

    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("PE 签名无效。")

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    optional_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]

    if machine != 0x8664 or optional_magic != 0x020B:
        raise ValueError("仅支持 x64 File Pilot 可执行文件。")

    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table_offset = pe_offset + 24 + optional_header_size

    if section_count < 1 or section_count > 96:
        raise ValueError("PE 节表数量无效。")

    if section_table_offset + section_count * 40 > len(data):
        raise ValueError("PE 节表越界。")

    sections = []

    for i in range(section_count):
        entry = section_table_offset + i * 40

        raw_size, raw_offset = struct.unpack_from("<II", data, entry + 16)

        if raw_size == 0:
            continue

        if raw_offset >= len(data) or raw_offset + raw_size > len(data):
            raise ValueError("PE 节的原始数据范围无效。")

        name_bytes = data[entry:entry + 8]

        try:
            name = name_bytes.rstrip(b"\x00").decode("ascii")
        except Exception:
            name = ""

        sections.append((name, raw_offset, raw_size))

    if not sections:
        raise ValueError("未找到有效的 PE 节。")

    return sections


def find_hits(data, sections, pattern):
    hits = []

    for _name, offset, size in sections:
        start = offset
        end = offset + size

        while True:
            idx = data.find(pattern, start, end)
            if idx < 0:
                break

            hits.append(idx)
            start = idx + 1

    return hits


def get_version_info(path):
    """
    读取 Windows 文件版本信息。
    只用于辅助判断是否是 File Pilot，不作为唯一依据。
    """
    if os.name != "nt":
        return {}

    try:
        import ctypes
        from ctypes import wintypes

        version = ctypes.windll.version
        handle = wintypes.DWORD()

        size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(handle))
        if size == 0:
            return {}

        buf = ctypes.create_string_buffer(size)

        if not version.GetFileVersionInfoW(str(path), handle, size, buf):
            return {}

        p = ctypes.c_void_p()
        length = ctypes.c_uint()

        if not version.VerQueryValueW(
            buf,
            r"\VarFileInfo\Translation",
            ctypes.byref(p),
            ctypes.byref(length),
        ):
            return {}

        raw = ctypes.string_at(p.value, length.value)
        result = {}
        fields = ("ProductName", "FileDescription", "OriginalFilename", "FileVersion")

        for i in range(0, max(0, len(raw) - 3), 4):
            lang, codepage = struct.unpack("<HH", raw[i:i + 4])
            prefix = f"\\StringFileInfo\\{lang:04X}{codepage:04X}\\"

            for field in fields:
                if field in result:
                    continue

                if version.VerQueryValueW(
                    buf,
                    prefix + field,
                    ctypes.byref(p),
                    ctypes.byref(length),
                ):
                    value = ctypes.cast(p, ctypes.c_wchar_p).value
                    if value:
                        result[field] = value

        return result

    except Exception:
        return {}


def build_patterns():
    original = ranges_to_bytes(ORIGINAL_RANGES)
    replacement = ranges_to_bytes(REPLACEMENT_RANGES)

    if len(original) != 136:
        raise ValueError("原始范围表长度不是 136 字节。")

    if len(replacement) == 0 or len(replacement) % 8 != 0:
        raise ValueError("替换范围表长度无效。")

    replacement_offset = FIRST_RANGE_INDEX * 8

    if replacement_offset < 0 or replacement_offset + len(replacement) > len(original):
        raise ValueError("替换范围超出原始范围表。")

    patched = bytearray(original)
    patched[replacement_offset:replacement_offset + len(replacement)] = replacement

    return original, bytes(patched)


def find_local_source():
    script_dir = Path(__file__).resolve().parent

    candidates = [
        Path.cwd() / "FPilot.exe",
        script_dir / "FPilot.exe",
        script_dir.parent / "FPilot.exe",
    ]

    seen = set()

    for candidate in candidates:
        try:
            candidate = candidate.resolve()
        except Exception:
            continue

        if candidate in seen:
            continue

        seen.add(candidate)

        if candidate.is_file():
            return candidate

    return None


def ask_source_gui():
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()

        try:
            root.attributes("-topmost", True)
        except Exception:
            pass

        path = filedialog.askopenfilename(
            title="选择原始 FPilot.exe",
            filetypes=[
                ("File Pilot 可执行文件", "FPilot.exe"),
                ("可执行文件", "*.exe"),
                ("所有文件", "*.*"),
            ],
        )

        root.destroy()

        if path:
            return Path(path)

        return None

    except Exception:
        try:
            text = input("请输入 FPilot.exe 的完整路径：").strip().strip('"')
            if text:
                return Path(text)
        except Exception:
            pass

        return None


def same_path(a, b):
    try:
        return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))
    except Exception:
        return os.path.normcase(str(a)) == os.path.normcase(str(b))


def choose_output(source_path, output_arg, out_hash):
    source_path = Path(source_path).resolve()

    if output_arg:
        out_path = Path(output_arg).expanduser().resolve()

        if out_path.exists():
            raise FileExistsError(f"输出文件已存在：{out_path}")

        if same_path(source_path, out_path):
            raise ValueError("输出文件不能与原始 EXE 相同。")

        return out_path, "new"

    out_dir = source_path.parent
    out_path = out_dir / "FPilot-CJK.exe"

    if out_path.exists():
        try:
            if sha256_file(out_path) == out_hash:
                return out_path, "exists"
        except Exception:
            pass

        counter = 2

        while True:
            candidate = out_dir / f"FPilot-CJK ({counter}).exe"

            if not candidate.exists():
                out_path = candidate
                break

            counter += 1

    if same_path(source_path, out_path):
        raise ValueError("输出文件不能与原始 EXE 相同。")

    return out_path, "new"


def write_output(out_path, data, expected_hash):
    out_path = Path(out_path)

    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = out_path.parent / (".fpilot-cjk-" + uuid.uuid4().hex + ".tmp")

    try:
        temp_path.write_bytes(data)

        actual_hash = sha256_file(temp_path)
        if actual_hash != expected_hash:
            raise IOError("临时输出文件 SHA-256 校验失败。")

        os.replace(temp_path, out_path)

    except PermissionError:
        raise RuntimeError(
            f"没有权限写入输出文件：{out_path}\n"
            "建议把 FPilot.exe 复制到非 Program Files 目录，或者使用 -o 指定有写入权限的输出路径。"
        )

    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


def apply_patch(source, output=None, force=False):
    source_path = Path(source).expanduser().resolve()

    if not source_path.is_file():
        raise FileNotFoundError(f"找不到源文件：{source_path}")

    if source_path.suffix.lower() != ".exe":
        raise ValueError("请选择 EXE 文件。")

    log(f"读取源文件：{source_path}")

    data = source_path.read_bytes()
    sections = parse_pe_sections(data)
    source_hash = sha256_bytes(data)

    version_info = get_version_info(source_path)
    version = version_info.get("FileVersion", "")

    if not force:
        product_text = " ".join(
            str(version_info.get(k, ""))
            for k in ("ProductName", "FileDescription", "OriginalFilename")
        ).strip()

        if product_text:
            if not re.search(r"(?i)(File\s*Pilot|FPilot)", product_text):
                raise ValueError("该文件版本信息不像 File Pilot。如确认没问题，可加 --force 跳过。")
        else:
            log("提示：未读取到文件版本信息，将继续依赖字节特征匹配。")

    original_pattern, patched_pattern = build_patterns()

    original_hits = find_hits(data, sections, original_pattern)
    patched_hits = find_hits(data, sections, patched_pattern)

    if len(original_hits) == 0 and len(patched_hits) == 1:
        return {
            "Status": "AlreadyPatched",
            "Source": str(source_path),
            "Version": version,
            "SourceSha256": source_hash,
            "TableOffset": patched_hits[0],
        }

    if len(original_hits) != 1 or len(patched_hits) != 0:
        raise ValueError(
            "安全特征匹配失败。\n"
            f"原始匹配：{len(original_hits)}；当前补丁匹配：{len(patched_hits)}。\n"
            "未写入文件。\n\n"
            "可能原因：\n"
            "1. 这不是原始未打补丁的 FPilot.exe；\n"
            "2. 该文件已经被旧补丁或其他补丁修改过；\n"
            "3. File Pilot 版本不匹配。"
        )

    out = bytearray(data)
    out[original_hits[0]:original_hits[0] + len(patched_pattern)] = patched_pattern

    post_original_hits = find_hits(out, sections, original_pattern)
    post_patched_hits = find_hits(out, sections, patched_pattern)

    if len(post_original_hits) != 0 or len(post_patched_hits) != 1:
        raise ValueError("内存中补丁后校验失败。未写入文件。")

    out_hash = sha256_bytes(out)

    out_path, status = choose_output(source_path, output, out_hash)

    if status == "exists":
        return {
            "Status": "OutputAlreadyExists",
            "Source": str(source_path),
            "Output": str(out_path),
            "Version": version,
            "SourceSha256": source_hash,
            "OutputSha256": out_hash,
            "TableOffset": original_hits[0],
        }

    write_output(out_path, out, out_hash)

    return {
        "Status": "Patched",
        "Source": str(source_path),
        "Output": str(out_path),
        "Version": version,
        "SourceSha256": source_hash,
        "OutputSha256": out_hash,
        "TableOffset": original_hits[0],
    }


def format_result(result):
    status = result.get("Status", "")

    if status == "Patched":
        return (
            "补丁成功。\n\n"
            f"来源：{result.get('Source')}\n"
            f"输出：{result.get('Output')}\n"
            f"版本：{result.get('Version') or '未知'}\n"
            f"表偏移：0x{result.get('TableOffset', 0):X}\n"
            f"来源 SHA-256：{result.get('SourceSha256')}\n"
            f"输出 SHA-256：{result.get('OutputSha256')}\n\n"
            "原始 EXE 未被修改。\n"
            "补丁后的 EXE 数字签名会失效，杀毒软件可能会报警。\n\n"
            "当前补丁包含：\n"
            "中文 / 中文标点 / 全角数字 / 韩文 / 常用符号 / △ 等几何符号。"
        )

    if status == "OutputAlreadyExists":
        return (
            "正确的补丁文件已经存在。\n\n"
            f"来源：{result.get('Source')}\n"
            f"输出：{result.get('Output')}\n"
            f"版本：{result.get('Version') or '未知'}\n"
            f"输出 SHA-256：{result.get('OutputSha256')}"
        )

    if status == "AlreadyPatched":
        return (
            "该文件已经打过当前补丁。\n\n"
            f"来源：{result.get('Source')}\n"
            f"版本：{result.get('Version') or '未知'}\n"
            f"表偏移：0x{result.get('TableOffset', 0):X}\n"
            f"SHA-256：{result.get('SourceSha256')}"
        )

    return str(result)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="File Pilot 中文 / 韩文 / 常用符号补丁。可把 FPilot.exe 拖到本脚本上运行。"
    )

    parser.add_argument(
        "source",
        nargs="*",
        help="原始 FPilot.exe 路径。可拖入。如果拖入多个，只处理第一个。"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="指定输出文件路径。默认生成 FPilot-CJK.exe。"
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="跳过文件版本信息检查。"
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="强制使用弹窗提示。"
    )

    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="结束后不等待回车。"
    )

    args = parser.parse_args(argv)

    exit_code = 0

    try:
        source = args.source[0] if args.source else None

        if not source:
            local_source = find_local_source()

            if local_source:
                source = str(local_source)
                log(f"自动找到源文件：{source}")
            else:
                selected = ask_source_gui()

                if selected:
                    source = str(selected)
                else:
                    raise FileNotFoundError("未找到 FPilot.exe，也没有选择源文件。")

        result = apply_patch(
            source=source,
            output=args.output,
            force=args.force,
        )

        message = format_result(result)
        show_message(message, TITLE, False, args.gui)

    except Exception as exc:
        show_message(f"补丁失败。\n\n{exc}", TITLE, True, args.gui)
        exit_code = 1

    if not args.no_pause:
        try:
            input("\n按回车键退出...")
        except Exception:
            pass

    return exit_code


if __name__ == "__main__":
    sys.exit(main())