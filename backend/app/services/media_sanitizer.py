"""
DRAIN-X Server-Side Media Sanitization and EXIF Redaction Service.

Ensures that uploaded incident photos have all potentially sensitive metadata
(GPS coordinates, device serial numbers, timestamps, camera models, personal EXIF/XMP tags)
completely stripped before storage. Re-encodes images into clean buffers with
decompression-bomb and memory limits.
"""

import io
import logging
from typing import Tuple
from PIL import Image, ImageOps, UnidentifiedImageError

logger = logging.getLogger("drainx.media")

# Maximum image pixel count to prevent decompression bomb attacks (e.g. 5000x5000 = 25MP)
MAX_IMAGE_PIXELS = 25_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# Maximum allowable dimension in either axis
MAX_DIMENSION = 6000

# Canonical mapping from detected PIL format to MIME type and file extension
FORMAT_SPEC = {
    "JPEG": {
        "mime": "image/jpeg",
        "ext": ".jpg",
        "save_format": "JPEG",
    },
    "PNG": {
        "mime": "image/png",
        "ext": ".png",
        "save_format": "PNG",
    },
    "WEBP": {
        "mime": "image/webp",
        "ext": ".webp",
        "save_format": "WEBP",
    },
}


class ImageProcessingError(Exception):
    """Raised when uploaded image content is invalid, malformed, or exceeds bounds."""
    pass


def sanitize_and_clean_image(
    raw_bytes: bytes,
    claimed_content_type: str = "",
) -> Tuple[bytes, str, str]:
    """
    Validates, strips metadata, and re-encodes an image file.

    Args:
        raw_bytes: The raw uploaded bytes.
        claimed_content_type: The MIME type sent in the HTTP Content-Type header.

    Returns:
        Tuple of (clean_bytes, output_mime_type, file_extension).

    Raises:
        ImageProcessingError: If the image is empty, malformed, unsupported, or exceeds dimensions.
    """
    if not raw_bytes:
        raise ImageProcessingError("Empty image file received.")

    try:
        src = Image.open(io.BytesIO(raw_bytes))
        src.load()  # Force decoding of image data to verify file integrity
    except (UnidentifiedImageError, ValueError, TypeError, OSError, SyntaxError) as err:
        logger.warning(f"Rejected unidentifiable or corrupt image upload: {err}")
        raise ImageProcessingError("Uploaded file is not a valid or recognizable image.")

    # 1. Format validation
    detected_format = (src.format or "").upper()
    if detected_format not in FORMAT_SPEC:
        logger.warning(f"Rejected unsupported image format: '{detected_format}'")
        raise ImageProcessingError(
            f"Unsupported image format '{detected_format}'. Allowed formats: JPEG, PNG, WebP."
        )

    # 2. Dimension and decompression safety check
    width, height = src.size
    if width <= 0 or height <= 0:
        raise ImageProcessingError("Invalid image dimensions.")

    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        logger.warning(f"Rejected oversized image dimensions: {width}x{height} exceeds {MAX_DIMENSION}px")
        raise ImageProcessingError(
            f"Image dimensions ({width}x{height}) exceed maximum allowable size of {MAX_DIMENSION}x{MAX_DIMENSION}."
        )

    try:
        # 3. Handle EXIF orientation so image isn't rotated when EXIF is stripped
        try:
            oriented = ImageOps.exif_transpose(src)
            if oriented is not None:
                src = oriented
        except Exception:
            pass  # Fall back to original orientation if EXIF transpose fails

        # 4. Construct fresh canvas with NO metadata or EXIF structures
        target_mode = "RGB" if detected_format == "JPEG" else ("RGBA" if src.mode in ("RGBA", "LA", "P") else "RGB")
        clean_canvas = Image.new(target_mode, src.size)

        if target_mode == "RGB" and src.mode in ("RGBA", "LA", "P"):
            converted_src = src.convert("RGB")
            clean_canvas.paste(converted_src)
        else:
            clean_canvas.paste(src)

        # 5. Re-encode into clean output bytes
        out_buf = io.BytesIO()
        spec = FORMAT_SPEC[detected_format]
        save_fmt = spec["save_format"]

        if save_fmt == "JPEG":
            clean_canvas.save(out_buf, format="JPEG", quality=85, optimize=True)
        elif save_fmt == "PNG":
            clean_canvas.save(out_buf, format="PNG", optimize=True)
        elif save_fmt == "WEBP":
            clean_canvas.save(out_buf, format="WEBP", quality=85)

        clean_bytes = out_buf.getvalue()
        return clean_bytes, spec["mime"], spec["ext"]

    except Image.DecompressionBombError as dbe:
        logger.warning(f"Rejected image decompression bomb: {dbe}")
        raise ImageProcessingError("Image exceeds safety decompression limits.")
    except Exception as exc:
        logger.error(f"Image sanitization failed: {exc}")
        raise ImageProcessingError("Failed to process and sanitize uploaded image.")
