// Re-encodes an image through a canvas before encryption. This strips EXIF/GPS and other metadata,
// normalises orientation, and bounds the size (docs/PROTOCOL.md §3.6). Browser only.
const MAX_SIDE = 2048;
const MAX_BYTES = 8 * 1024 * 1024;

export interface PreparedImage {
  bytes: Uint8Array;
  mime: "image/webp" | "image/jpeg";
  w: number;
  h: number;
}

async function encode(
  canvas: HTMLCanvasElement,
  type: string,
  quality: number,
): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob(resolve, type, quality));
}

export async function prepareImage(file: Blob): Promise<PreparedImage> {
  if (!file.type.startsWith("image/")) throw new Error("not an image");
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  } catch {
    throw new Error("could not decode this image");
  }
  try {
    let scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
    for (let attempt = 0; attempt < 6; attempt++) {
      const w = Math.max(1, Math.round(bitmap.width * scale));
      const h = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("canvas unavailable");
      ctx.drawImage(bitmap, 0, 0, w, h);
      const quality = attempt < 3 ? 0.85 : 0.7;
      // Some browsers silently fall back to PNG when they cannot encode WebP.
      let blob = await encode(canvas, "image/webp", quality);
      let mime: PreparedImage["mime"] = "image/webp";
      if (!blob || blob.type !== "image/webp") {
        blob = await encode(canvas, "image/jpeg", quality);
        mime = "image/jpeg";
      }
      if (!blob || blob.type !== mime) throw new Error("could not encode image");
      if (blob.size <= MAX_BYTES)
        return { bytes: new Uint8Array(await blob.arrayBuffer()), mime, w, h };
      scale *= 0.7;
    }
    throw new Error("image is too large");
  } finally {
    bitmap.close();
  }
}
