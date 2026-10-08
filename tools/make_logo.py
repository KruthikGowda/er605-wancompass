"""Draw the NetPulse bot logo (docs/assets/netpulse-bot.png). Needs Pillow (dev machine only).

    python -m tools.make_logo
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

SIZE = 640
SCALE = 4  # draw big, then downsample for smooth edges
OUT = Path(__file__).resolve().parent.parent / "docs" / "assets" / "netpulse-bot.png"

BG_INNER = (18, 110, 120)   # teal
BG_OUTER = (8, 38, 52)      # deep navy
WAN1 = (91, 147, 240)       # Example ISP A blue (dashboard --wan1)
WAN2 = (240, 150, 74)       # Example ISP B orange (dashboard --wan2)


def main() -> None:
    s = SIZE * SCALE
    img = Image.new("RGB", (s, s), BG_OUTER)

    # Radial gradient background.
    grad = Image.radial_gradient("L").resize((s, s))
    inner = Image.new("RGB", (s, s), BG_INNER)
    img = Image.composite(img, inner, grad)

    d = ImageDraw.Draw(img)
    cx, cy = s // 2, s // 2
    u = s / 640

    # Pulse line (heartbeat), kept inside the circle Telegram crops to.
    pts = [(-230, 0), (-120, 0), (-85, -40), (-50, 0), (-20, 0), (15, -170), (55, 150),
           (95, -60), (120, 0), (230, 0)]
    line = [(cx + x * u, cy + y * u) for x, y in pts]

    glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(glow).line(line, fill=(120, 255, 230, 150), width=int(46 * u), joint="curve")
    glow = glow.filter(ImageFilter.GaussianBlur(18 * u))
    img.paste(glow, (0, 0), glow)
    d.line(line, fill=(255, 255, 255), width=int(26 * u), joint="curve")
    for x, y in (line[0], line[-1]):
        r = 13 * u
        d.ellipse((x - r, y - r, x + r, y + r), fill=(255, 255, 255))

    # Two connection dots at the ends: Example ISP A (left) and Example ISP B (right).
    for (x, y), color in ((line[0], WAN1), (line[-1], WAN2)):
        r = 34 * u
        d.ellipse((x - r, y - r, x + r, y + r), fill=color, outline=(255, 255, 255), width=int(10 * u))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.resize((SIZE, SIZE), Image.LANCZOS).save(OUT, optimize=True)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
