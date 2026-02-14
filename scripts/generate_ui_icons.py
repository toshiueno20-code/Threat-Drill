"""Generate UI icons (and diagrams) using Gemini 2.5 Flash Image (aka "Nano Banana").

This script:
- Uses the local Gatekeeper `.env` API key (AI Studio) via `gatekeeper.config.settings`.
- Generates a small, consistent icon set as PNGs.
- Saves outputs under `gatekeeper/app/static/assets/icons/`.
 - Can also render a high-res architecture diagram PNG for docs/articles.

Notes:
- The script does not print or log the API key.
- Rerunning will overwrite existing files unless `--skip-existing` is passed.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image, ImageFilter

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gatekeeper.config import settings  # noqa: E402


@dataclass(frozen=True)
class IconSpec:
    filename: str
    description: str


ICON_SPECS: list[IconSpec] = [
    IconSpec(
        "brand.png",
        "ThreatDrill brand icon: a minimal shield combined with an AI/circuit motif and a subtle target/reticle, "
        "conveying 'AI performs security checks' and 'security drill/exercise'.",
    ),
    IconSpec("nav-dashboard.png", "A dashboard grid icon"),
    IconSpec("nav-redteam.png", "A red team operations icon (non-weapon abstract)"),
    IconSpec("nav-blueteam.png", "A blue team defense icon"),
    IconSpec("nav-purpleteam.png", "A collaboration / coordination icon"),
    IconSpec("nav-api.png", "An API / integration icon"),
    # Stat icons: keep a consistent monoline style (same stroke weight, no background shapes).
    IconSpec(
        "stat-requests.png",
        "Bold monoline radar pulse icon for request count. Absolutely no filled background tile. Legible at 20x20 px.",
    ),
    IconSpec(
        "stat-blocked.png",
        "Bold monoline shield with a clear X mark. No inner details. Must be legible at 20x20 px.",
    ),
    IconSpec("stat-attack-skills.png", "Monoline wrench+crosshair (or tool+target) icon for red-team checks count"),
    IconSpec(
        "stat-defense-skills.png",
        "Bold monoline shield with a large check mark. No inner rings. Must be legible at 20x20 px.",
    ),
    IconSpec(
        "stat-detection-rate.png",
        "Bold monoline radar/scan icon: 2 arcs + center dot + one sweep line. No fine rings/dots. Legible at 20x20 px.",
    ),
    IconSpec(
        "stat-defense-score.png",
        "Bold monoline bullseye: 2 thick rings + center dot (no extra details). Must be legible at 20x20 px.",
    ),
    IconSpec("empty-inbox.png", "An empty inbox / no events icon"),
    IconSpec("empty-tools.png", "A tools icon for empty skills list"),
    IconSpec("empty-search.png", "A search icon for 'select a log entry'"),
    IconSpec("empty-map.png", "A map / coverage icon"),
]


def _key_out_background(img: Image.Image) -> Image.Image:
    """Best-effort transparency fix.

    Some image models return a baked-in checkerboard/solid background even when asked for
    transparency. We sample border pixels to guess background colors, then key them out.

    This is intentionally conservative: these UI icons should be light strokes/fills on
    transparent background, so removing dark/flat backgrounds is desirable.
    """

    img = img.convert("RGBA")
    w, h = img.size
    px = img.load()

    # Sample a 3px border.
    border: list[tuple[int, int, int]] = []
    band = 3
    for y in range(h):
        for x in range(w):
            if x < band or x >= w - band or y < band or y >= h - band:
                r, g, b, a = px[x, y]
                if a == 0:
                    continue
                border.append((r, g, b))

    if not border:
        return img

    # Quantize border colors and pick the top few as background candidates.
    def q(c: tuple[int, int, int]) -> tuple[int, int, int]:
        return (c[0] // 16, c[1] // 16, c[2] // 16)

    counts: dict[tuple[int, int, int], int] = {}
    for c in border:
        qc = q(c)
        counts[qc] = counts.get(qc, 0) + 1

    top_bins = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:4]
    bg_bins = {b for b, _n in top_bins}

    # Build a per-pixel mask and set alpha to 0 if it matches background bins closely.
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out_px = out.load()

    # Thresholds chosen for typical dark/neutral backgrounds and checkerboards.
    tol = 28  # per-channel tolerance
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a == 0:
                continue
            qb = q((r, g, b))
            if qb in bg_bins:
                out_px[x, y] = (r, g, b, 0)
                continue

            # Also allow approximate matches to the top bins to remove alternating checker squares.
            is_bg = False
            for br, bg, bb in bg_bins:
                rr, gg, bb2 = br * 16 + 8, bg * 16 + 8, bb * 16 + 8
                if abs(r - rr) <= tol and abs(g - gg) <= tol and abs(b - bb2) <= tol:
                    is_bg = True
                    break
            out_px[x, y] = (r, g, b, 0 if is_bg else a)

    return out


def _normalize_monoline_white(img: Image.Image) -> Image.Image:
    """Force monoline icons to be bright and visible on dark UIs.

    Some generations come back as semi-transparent mid-gray strokes which become
    invisible when displayed at ~20px. For UI stat icons we normalize:
    - RGB -> white
    - alpha -> boosted by luminance (capped)
    """

    img = img.convert("RGBA")
    w, h = img.size
    px = img.load()

    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a == 0:
                continue
            lum = int(0.2126 * r + 0.7152 * g + 0.0722 * b)
            na = max(a, lum)
            na = int(min(255, na * 1.6))
            px[x, y] = (255, 255, 255, na)

    return img


def _thicken_alpha(img: Image.Image, *, radius: int = 1) -> Image.Image:
    """Thicken thin strokes by dilating the alpha channel slightly."""

    if radius <= 0:
        return img.convert("RGBA")

    img = img.convert("RGBA")
    r, g, b, a = img.split()
    # MaxFilter size must be odd and >= 3.
    size = 2 * radius + 1
    a2 = a.filter(ImageFilter.MaxFilter(size=size))
    return Image.merge("RGBA", (r, g, b, a2))


def _remove_large_solid_fill(img: Image.Image) -> Image.Image:
    """Remove a large solid fill block (common failure: model draws a white tile background).

    We detect the most common near-white opaque color and, if it occupies a large fraction
    of the image, key it out.
    """

    img = img.convert("RGBA")
    w, h = img.size
    px = list(img.getdata())

    # Consider "near-white" + opaque as the likely unwanted fill.
    solid = [(r, g, b) for (r, g, b, a) in px if a > 240 and r > 240 and g > 240 and b > 240]
    if not solid:
        return img

    from collections import Counter

    c = Counter(solid)
    (sr, sg, sb), count = c.most_common(1)[0]
    frac = count / (w * h)
    # Only key out if it looks like a tile background, not just thick strokes.
    if frac < 0.20:
        return img

    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out_px = out.load()
    in_px = img.load()
    tol = 18
    for y in range(h):
        for x in range(w):
            r, g, b, a = in_px[x, y]
            if a > 240 and abs(r - sr) <= tol and abs(g - sg) <= tol and abs(b - sb) <= tol:
                out_px[x, y] = (r, g, b, 0)
            else:
                out_px[x, y] = (r, g, b, a)
    return out


def _extract_first_image_bytes(resp: Any) -> tuple[bytes, str]:
    """Return (image_bytes, mime_type)."""
    # google-genai responses usually have candidates[].content.parts[].inline_data
    candidates = getattr(resp, "candidates", None) or []
    for cand in candidates:
        content = getattr(cand, "content", None)
        parts = getattr(content, "parts", None) or []
        for part in parts:
            inline = getattr(part, "inline_data", None)
            if inline is None:
                continue
            mime = getattr(inline, "mime_type", None) or "image/png"
            data = getattr(inline, "data", None)
            if not data:
                continue
            if isinstance(data, (bytes, bytearray)):
                return (bytes(data), mime)
            if isinstance(data, str):
                try:
                    return (base64.b64decode(data), mime)
                except Exception:
                    continue

    # Fallback: some SDK versions expose `parts` directly on response.
    parts = getattr(resp, "parts", None) or []
    for part in parts:
        inline = getattr(part, "inline_data", None)
        if inline is None:
            continue
        mime = getattr(inline, "mime_type", None) or "image/png"
        data = getattr(inline, "data", None)
        if not data:
            continue
        if isinstance(data, (bytes, bytearray)):
            return (bytes(data), mime)
        if isinstance(data, str):
            return (base64.b64decode(data), mime)

    raise RuntimeError("No image data found in Gemini response.")


def _fit_contain(
    img: Image.Image,
    *,
    width: int,
    height: int,
    bg: tuple[int, int, int] = (255, 255, 255),
) -> Image.Image:
    """Resize to fit within (width,height) without cropping, add padding with solid background."""

    img = img.convert("RGBA")
    src_w, src_h = img.size
    if src_w <= 0 or src_h <= 0:
        raise RuntimeError("Invalid image dimensions from model.")

    scale = min(width / src_w, height / src_h)
    new_w = max(1, int(src_w * scale))
    new_h = max(1, int(src_h * scale))
    resized = img.resize((new_w, new_h), Image.Resampling.LANCZOS)

    canvas = Image.new("RGBA", (width, height), (bg[0], bg[1], bg[2], 255))
    x = (width - new_w) // 2
    y = (height - new_h) // 2
    canvas.alpha_composite(resized, (x, y))
    return canvas.convert("RGB")


def _generate_png_from_prompt(client: Any, *, model: str, prompt: str) -> Image.Image:
    """Generate an image from a freeform prompt using the image model."""

    from google.genai import types  # type: ignore

    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_modalities=["TEXT", "IMAGE"],
        ),
    )

    data, _mime = _extract_first_image_bytes(resp)
    return Image.open(io.BytesIO(data))


def _generate_icon_png(client: Any, *, model: str, spec: IconSpec, size: int) -> Image.Image:
    # Keep prompts short and consistent to avoid style drift.
    prompt = (
        "Generate a minimal UI icon.\n"
        "Constraints:\n"
        "- 1:1 square, centered.\n"
        "- Flat vector-like look.\n"
        "- Monoline style with consistent stroke weight (approximately 4–6px at 128x128).\n"
        "- Rounded line caps/joins.\n"
        "- Must remain clearly visible when scaled down to 20x20 px.\n"
        "- Avoid hairline strokes, tiny dots, and dense detail.\n"
        "- Use fully opaque strokes/fills (no low-alpha gray).\n"
        "- Transparent background (true alpha, no solid fill).\n"
        "- Do NOT include any checkerboard transparency pattern.\n"
        "- Do NOT include a black/colored square or rounded-rect background behind the icon.\n"
        "- Single-color white or very light gray strokes/fill suitable for dark UI.\n"
        "- No text, no letters, no words.\n"
        "- Simple, recognizable silhouette.\n\n"
        f"Icon concept: {spec.description}\n"
    )

    # Import lazily so the repo can still import without google-genai at import time.
    from google.genai import types  # type: ignore

    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_modalities=["TEXT", "IMAGE"],
        ),
    )

    data, _mime = _extract_first_image_bytes(resp)
    img = Image.open(io.BytesIO(data)).convert("RGBA")
    img = _key_out_background(img)
    if spec.filename.startswith("stat-"):
        img = _normalize_monoline_white(img)
        img = _remove_large_solid_fill(img)
        img = _thicken_alpha(img, radius=1)

    # Normalize to a consistent square size for UI.
    # Use a contain fit (no cropping) and center on transparent canvas.
    img.thumbnail((size, size), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    x = (size - img.width) // 2
    y = (size - img.height) // 2
    canvas.alpha_composite(img, (x, y))
    return canvas


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--architecture",
        action="store_true",
        help="Generate a high-res architecture diagram PNG (for Zenn/docs) instead of UI icons.",
    )
    ap.add_argument(
        "--arch-prompt-file",
        default="docs/diagrams/nano-banana_architecture_prompt.md",
        help="Prompt file for architecture diagram generation.",
    )
    ap.add_argument(
        "--arch-out",
        default="images/threatdrill-architecture.png",
        help="Output path for architecture diagram PNG.",
    )
    ap.add_argument("--arch-width", type=int, default=1920)
    ap.add_argument("--arch-height", type=int, default=1080)
    ap.add_argument("--out-dir", default="gatekeeper/app/static/assets/icons")
    ap.add_argument("--model", default=os.environ.get("GEMINI_ICON_MODEL", "gemini-2.5-flash-image"))
    ap.add_argument("--size", type=int, default=128)
    ap.add_argument("--skip-existing", action="store_true")
    ap.add_argument(
        "--only",
        action="append",
        default=[],
        help="Generate only these filenames (repeatable). Example: --only empty-inbox.png",
    )
    args = ap.parse_args()

    if not settings.api_key:
        raise SystemExit("API_KEY (or GEMINI_API_KEY) is required in .env to generate icons.")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from google import genai  # type: ignore

    client = genai.Client(api_key=settings.api_key)

    if args.architecture:
        prompt_path = (_REPO_ROOT / args.arch_prompt_file).resolve()
        if not prompt_path.exists():
            raise SystemExit(f"Prompt file not found: {prompt_path}")

        prompt = prompt_path.read_text(encoding="utf-8")
        out_path = (_REPO_ROOT / args.arch_out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if args.skip_existing and out_path.exists():
            return 0

        # Backup existing file, if any.
        if out_path.exists():
            bak = out_path.with_suffix(out_path.suffix + ".prev.png")
            try:
                out_path.replace(bak)
            except Exception:
                pass

        img = _generate_png_from_prompt(client, model=args.model, prompt=prompt)
        img2 = _fit_contain(img, width=args.arch_width, height=args.arch_height, bg=(255, 255, 255))
        img2.save(out_path, format="PNG", optimize=True)
        return 0

    only: set[str] = set(args.only or [])
    for spec in ICON_SPECS:
        if only and spec.filename not in only:
            continue
        path = out_dir / spec.filename
        if args.skip_existing and path.exists():
            continue

        img = _generate_icon_png(client, model=args.model, spec=spec, size=args.size)
        img.save(path, format="PNG", optimize=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
