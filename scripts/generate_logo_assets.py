#! /usr/bin/env python3
"""Generate PNG and ICO assets from the official SANITIZE SVG geometry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ASSETS_ROOT = ROOT / "assets" / "logo"
PNG_DIR = ASSETS_ROOT / "png"
ICO_DIR = ASSETS_ROOT / "ico"
VARIANTS_DIR = ASSETS_ROOT / "variants"
PACKAGING_ASSETS = ROOT / "packaging" / "assets"

SIZES = [1024, 512, 256, 128, 64, 32]
ICO_SIZES = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]


@dataclass(frozen=True)
class Variant:
    name: str


VARIANTS = [
    Variant("dark"),
    Variant("light"),
    Variant("minimal"),
]


def scale(size: int, value: float) -> int:
    return int(round(size * (value / 512.0)))


def poly(points: list[tuple[float, float]], size: int) -> list[tuple[int, int]]:
    return [(scale(size, x), scale(size, y)) for x, y in points]


def draw_check(draw: ImageDraw.ImageDraw, size: int, path: list[tuple[float, float]], color: str, width: float) -> None:
    draw.line(poly(path, size), fill=color, width=max(1, scale(size, width)), joint="curve")


def draw_dark(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    hex_points = [(256, 40), (446.526, 150), (446.526, 362), (256, 472), (65.4745, 362), (65.4745, 150)]
    draw.polygon(poly(hex_points, size), fill="#1A2B42")

    draw.rounded_rectangle(
        [scale(size, 160), scale(size, 140), scale(size, 352), scale(size, 372)],
        radius=scale(size, 8),
        fill="#F5F5F5",
    )
    fold = poly([(352, 180), (312, 140), (344, 140), (352, 148)], size)
    draw.polygon(fold, fill="#D1D5DB")

    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 180), scale(size, 284), scale(size, 192)],
        radius=scale(size, 2),
        fill="#94A3B8",
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 210), scale(size, 328), scale(size, 222)],
        radius=scale(size, 2),
        fill="#94A3B8",
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 240), scale(size, 304), scale(size, 258)],
        radius=scale(size, 4),
        fill="#EF4444",
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 280), scale(size, 328), scale(size, 292)],
        radius=scale(size, 2),
        fill="#94A3B8",
    )

    draw.ellipse(
        [scale(size, 290), scale(size, 310), scale(size, 350), scale(size, 370)],
        fill="#2ECC71",
    )
    draw_check(draw, size, [(310, 340), (317, 347), (332, 332)], "#FFFFFF", 6)
    return img


def draw_light(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    hex_points = [(256, 50), (437.897, 155), (437.897, 357), (256, 462), (74.1026, 357), (74.1026, 155)]
    draw.line(poly(hex_points + [hex_points[0]], size), fill="#1A2B42", width=max(1, scale(size, 20)), joint="curve")

    draw.rounded_rectangle(
        [scale(size, 160), scale(size, 140), scale(size, 352), scale(size, 372)],
        radius=scale(size, 8),
        fill="#FFFFFF",
        outline="#D1D5DB",
        width=max(1, scale(size, 2)),
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 180), scale(size, 284), scale(size, 190)],
        radius=scale(size, 2),
        fill="#94A3B8",
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 210), scale(size, 328), scale(size, 220)],
        radius=scale(size, 2),
        fill="#94A3B8",
    )
    draw.rounded_rectangle(
        [scale(size, 184), scale(size, 240), scale(size, 304), scale(size, 260)],
        radius=scale(size, 4),
        fill="#EF4444",
    )

    draw.ellipse(
        [scale(size, 305), scale(size, 315), scale(size, 355), scale(size, 365)],
        fill="#2ECC71",
    )
    draw_check(draw, size, [(322, 340), (327, 345), (338, 334)], "#FFFFFF", 5)
    return img


def draw_minimal(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    hex_points = [(256, 40), (446.526, 150), (446.526, 362), (256, 472), (65.4745, 362), (65.4745, 150)]
    draw.polygon(poly(hex_points, size), fill="#000000")

    draw.rounded_rectangle(
        [scale(size, 160), scale(size, 140), scale(size, 352), scale(size, 372)],
        radius=scale(size, 4),
        fill="#FFFFFF",
    )
    draw.rounded_rectangle(
        [scale(size, 180), scale(size, 180), scale(size, 332), scale(size, 195)],
        radius=scale(size, 2),
        fill="#000000",
    )
    draw.rounded_rectangle(
        [scale(size, 180), scale(size, 210), scale(size, 332), scale(size, 250)],
        radius=scale(size, 2),
        fill="#000000",
    )
    draw.rectangle(
        [scale(size, 190), scale(size, 225), scale(size, 250), scale(size, 235)],
        fill="#FFFFFF",
    )
    draw.rounded_rectangle(
        [scale(size, 180), scale(size, 265), scale(size, 280), scale(size, 280)],
        radius=scale(size, 2),
        fill="#000000",
    )
    return img


def draw_variant(name: str, size: int) -> Image.Image:
    if name == "dark":
        return draw_dark(size)
    if name == "light":
        return draw_light(size)
    if name == "minimal":
        return draw_minimal(size)
    raise ValueError(f"Unknown variant: {name}")


def ensure_dirs() -> None:
    for directory in [PNG_DIR, ICO_DIR, PACKAGING_ASSETS, VARIANTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def clean_previous_exports() -> None:
    for root in [PNG_DIR, ICO_DIR]:
        if not root.exists():
            continue
        for item in root.rglob("*"):
            if item.is_file():
                item.unlink()


def refresh_primary_links() -> None:
    dark_svg = VARIANTS_DIR / "sanitize-logo-dark.svg"
    if dark_svg.exists():
        (ROOT / "assets" / "sanitize-logo.svg").write_text(dark_svg.read_text(encoding="utf-8"), encoding="utf-8")
        (PACKAGING_ASSETS / "config-sanitizer.svg").write_text(dark_svg.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    ensure_dirs()
    clean_previous_exports()
    refresh_primary_links()

    for variant in VARIANTS:
        out_dir = PNG_DIR / variant.name
        out_dir.mkdir(parents=True, exist_ok=True)
        icon_256 = None

        for size in SIZES:
            image = draw_variant(variant.name, size)
            image.save(out_dir / f"sanitize-logo-{variant.name}-{size}.png", format="PNG")
            if size == 256:
                icon_256 = image

        if icon_256 is None:
            icon_256 = draw_variant(variant.name, 256)
        icon_256.save(ICO_DIR / f"sanitize-logo-{variant.name}.ico", format="ICO", sizes=ICO_SIZES)

        if variant.name == "dark":
            icon_256.save(PACKAGING_ASSETS / "config-sanitizer.ico", format="ICO", sizes=ICO_SIZES)

    print(f"Generated raster assets in: {ASSETS_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
