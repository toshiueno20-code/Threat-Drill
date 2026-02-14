"""Generate UI icons using Gemini 2.5 Flash Image (aka "Nano Banana").

This script:
- Uses the local Gatekeeper `.env` API key (AI Studio) via `gatekeeper.config.settings`.
- Generates a small, consistent icon set as PNGs.
- Saves outputs under `gatekeeper/app/static/assets/icons/`.

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

from PIL import Image

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gatekeeper.config import settings  # noqa: E402


@dataclass(frozen=True)
class IconSpec:
    filename: str
    description: str


ICON_SPECS: list[IconSpec] = [
    IconSpec("brand.png", "A shield-like brand mark for a security operations dashboard"),
    IconSpec("nav-dashboard.png", "A dashboard grid icon"),
    IconSpec("nav-redteam.png", "A red team operations icon (non-weapon abstract)"),
    IconSpec("nav-blueteam.png", "A blue team defense icon"),
    IconSpec("nav-purpleteam.png", "A collaboration / coordination icon"),
    IconSpec("nav-api.png", "An API / integration icon"),
    IconSpec("stat-requests.png", "A telemetry / activity icon for request count"),
    IconSpec("stat-blocked.png", "A block / stop icon for threats blocked"),
    IconSpec("stat-attack-skills.png", "A toolset icon for number of red-team checks"),
    IconSpec("stat-defense-skills.png", "A shield-check icon for blue-team skills"),
    IconSpec("stat-detection-rate.png", "A success / coverage icon"),
    IconSpec("stat-defense-score.png", "A target / bullseye icon for posture score"),
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


def _generate_icon_png(client: Any, *, model: str, spec: IconSpec, size: int) -> Image.Image:
    # Keep prompts short and consistent to avoid style drift.
    prompt = (
        "Generate a minimal UI icon.\n"
        "Constraints:\n"
        "- 1:1 square, centered.\n"
        "- Flat vector-like look.\n"
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
