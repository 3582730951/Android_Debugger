#!/usr/bin/env python3
import argparse
import json
import math
import pathlib
import struct
import sys
from typing import List, Tuple


MAGIC = b"R3IA"
VERSION = 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pack SVG icons into RGBA atlas + metadata")
    p.add_argument("--manifest", required=True, help="Path to manifest.json")
    p.add_argument("--icons", required=True, help="Directory containing svg files")
    p.add_argument("--out-bin", required=True, help="Output IconAtlas.bin")
    p.add_argument("--out-header", required=True, help="Output IconAtlasMeta.h")
    p.add_argument("--tile", type=int, default=32, help="Per-icon tile size in pixels")
    p.add_argument("--padding", type=int, default=4, help="Inner icon padding in pixels")
    p.add_argument("--preview", default="", help="Optional output PNG preview path")
    return p.parse_args()


def load_manifest(path: pathlib.Path) -> List[Tuple[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        icons = data.get("icons", [])
    elif isinstance(data, list):
        icons = data
    else:
        raise ValueError("manifest format invalid")

    out: List[Tuple[str, str]] = []
    for i, item in enumerate(icons):
        if not isinstance(item, dict):
            raise ValueError(f"manifest item #{i} must be object")
        icon_id = item.get("id")
        icon_file = item.get("file")
        if not icon_id or not icon_file:
            raise ValueError(f"manifest item #{i} missing id/file")
        out.append((str(icon_id), str(icon_file)))
    if not out:
        raise ValueError("manifest has no icons")
    return out


def next_pow2(v: int) -> int:
    x = 1
    while x < v:
        x <<= 1
    return x


def import_skia():
    try:
        import skia  # type: ignore
        return skia
    except Exception as exc:
        raise RuntimeError(
            "skia-python is required to rasterize SVG. Install with: python -m pip install skia-python"
        ) from exc


def render_svg_tile(skia, svg_text: str, tile: int, padding: int) -> bytes:
    normalized = svg_text.replace("currentColor", "#FFFFFF")
    stream = skia.MemoryStream(normalized.encode("utf-8"))
    dom = skia.SVGDOM.MakeFromStream(stream)
    if dom is None:
        raise RuntimeError("failed to parse SVG document")

    surface = skia.Surface(tile, tile)
    canvas = surface.getCanvas()
    canvas.clear(skia.ColorTRANSPARENT)

    draw_size = max(1, tile - padding * 2)
    canvas.save()
    canvas.translate(float(padding), float(padding))
    dom.setContainerSize(skia.Size(float(draw_size), float(draw_size)))
    dom.render(canvas)
    canvas.restore()

    image = surface.makeImageSnapshot()
    rgba = bytes(image.tobytes())
    if len(rgba) != tile * tile * 4:
        raise RuntimeError("unexpected tile byte size")
    return rgba


def build_atlas(icon_rasters: List[Tuple[str, bytes]], tile: int):
    count = len(icon_rasters)
    cols = max(1, math.ceil(math.sqrt(count)))
    rows = math.ceil(count / cols)
    atlas_w = next_pow2(cols * tile)
    atlas_h = next_pow2(rows * tile)

    atlas = bytearray(atlas_w * atlas_h * 4)
    entries: List[Tuple[str, int, int, int, int]] = []

    for idx, (icon_id, tile_rgba) in enumerate(icon_rasters):
        x = (idx % cols) * tile
        y = (idx // cols) * tile
        entries.append((icon_id, x, y, tile, tile))

        for row in range(tile):
            src_off = row * tile * 4
            dst_off = ((y + row) * atlas_w + x) * 4
            atlas[dst_off:dst_off + tile * 4] = tile_rgba[src_off:src_off + tile * 4]

    return atlas_w, atlas_h, entries, bytes(atlas)


def write_bin(path: pathlib.Path,
              atlas_w: int,
              atlas_h: int,
              entries: List[Tuple[str, int, int, int, int]],
              rgba: bytes):
    table = bytearray()
    for icon_id, x, y, w, h in entries:
        name = icon_id.encode("utf-8")
        if len(name) > 0xFFFF:
            raise ValueError(f"icon id too long: {icon_id}")
        table.extend(struct.pack("<HHHHHH", len(name), 0, x, y, w, h))
        table.extend(name)

    header = struct.pack("<4sIIIII", MAGIC, VERSION, atlas_w, atlas_h, len(entries), len(table))

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(header)
        f.write(table)
        f.write(rgba)


def write_header(path: pathlib.Path,
                 atlas_w: int,
                 atlas_h: int,
                 entries: List[Tuple[str, int, int, int, int]]):
    lines: List[str] = []
    lines.append("#pragma once")
    lines.append("#include <cstdint>")
    lines.append("")
    lines.append("struct R3SvgIconMeta {")
    lines.append("  const char* id;")
    lines.append("  std::uint16_t x;")
    lines.append("  std::uint16_t y;")
    lines.append("  std::uint16_t w;")
    lines.append("  std::uint16_t h;")
    lines.append("};")
    lines.append("")
    lines.append(f"static constexpr std::uint32_t kR3SvgAtlasWidth = {atlas_w}u;")
    lines.append(f"static constexpr std::uint32_t kR3SvgAtlasHeight = {atlas_h}u;")
    lines.append("static constexpr R3SvgIconMeta kR3SvgIconMeta[] = {")
    for icon_id, x, y, w, h in entries:
        safe_id = icon_id.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'  {{"{safe_id}", {x}u, {y}u, {w}u, {h}u}},')
    lines.append("};")
    lines.append(f"static constexpr std::uint32_t kR3SvgIconCount = {len(entries)}u;")
    lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_preview(path: pathlib.Path, atlas_w: int, atlas_h: int, rgba: bytes):
    if not path:
        return
    try:
        from PIL import Image  # type: ignore
    except Exception:
        return
    img = Image.frombytes("RGBA", (atlas_w, atlas_h), rgba)
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    img.save(path)


def main() -> int:
    args = parse_args()
    if args.tile < 8:
        raise ValueError("tile too small")
    if args.padding < 0 or args.padding * 2 >= args.tile:
        raise ValueError("padding invalid")

    manifest = pathlib.Path(args.manifest)
    icons_dir = pathlib.Path(args.icons)
    out_bin = pathlib.Path(args.out_bin)
    out_header = pathlib.Path(args.out_header)

    icon_entries = load_manifest(manifest)
    skia = import_skia()

    rasters: List[Tuple[str, bytes]] = []
    for icon_id, icon_file in icon_entries:
        svg_path = icons_dir / icon_file
        if not svg_path.exists():
            raise FileNotFoundError(f"icon not found: {svg_path}")
        svg_text = svg_path.read_text(encoding="utf-8")
        tile_rgba = render_svg_tile(skia, svg_text, args.tile, args.padding)
        rasters.append((icon_id, tile_rgba))

    atlas_w, atlas_h, atlas_entries, rgba = build_atlas(rasters, args.tile)
    write_bin(out_bin, atlas_w, atlas_h, atlas_entries, rgba)
    write_header(out_header, atlas_w, atlas_h, atlas_entries)
    if args.preview:
        write_preview(pathlib.Path(args.preview), atlas_w, atlas_h, rgba)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
