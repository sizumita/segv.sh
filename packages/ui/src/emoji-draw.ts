// Which emoji this device can draw, so that the picker offers none that would show as an empty box: the newest Emoji
// version whose test emoji the device's fonts draw in color (§11.12 leaves what a client shows to its own tables).

/** The emoji fonts of the platforms, as the stylesheet's --emoji names them. */
const FONT = '100px "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif';

/**
 * Whether `e` is drawn as one color glyph: drawn in black and then in white into one pixel, a color glyph gives the
 * same pixel both times, and a missing one (an empty box, or nothing) does not.
 */
function inColor(ctx: CanvasRenderingContext2D, e: string): boolean {
  const pixel = (fill: string): string => {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, 1, 1);
    ctx.scale(0.01, 0.01);
    ctx.font = FONT;
    ctx.textBaseline = "top";
    ctx.fillStyle = fill;
    ctx.fillText(e, 0, 0);
    return ctx.getImageData(0, 0, 1, 1).data.join(",");
  };
  const black = pixel("#000");
  return black === pixel("#fff") && !black.startsWith("0,0,0,");
}

let newest: number | undefined;

/**
 * The newest Emoji version that this device draws, from `probes` (one emoji per version, newest first); 10 when it
 * draws none of them, and Infinity when it cannot tell (no canvas, or a browser that blurs what a canvas reads back, as
 * some do against fingerprinting): then the picker offers every emoji.
 */
export function newestDrawn(probes: [number, string][]): number {
  if (newest !== undefined) return newest;
  newest = Infinity;
  try {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (ctx && inColor(ctx, "😀")) newest = probes.find(([, e]) => inColor(ctx, e))?.[0] ?? 10;
  } catch {
    // no canvas: offer everything
  }
  return newest;
}
