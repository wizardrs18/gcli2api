"""上传默认封面到 S3

读取 deafult_cover/ 目录下的 PNG 文件，处理为 WebP 标准版 + 缩略图，
上传到 S3 公共桶 manbo.chat，命名为 covers/deafult_cover_1.webp 等。

用法:
    python upload_default_covers.py
"""

import io
import os
import sys
from pathlib import Path

import boto3
from PIL import Image

# ============================================================================
# AWS / S3 配置
# ============================================================================
AWS_ACCESS_KEY_ID = "AKIA4UWLDN6342X6TZPY"
AWS_SECRET_ACCESS_KEY = "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"
AWS_REGION = "ap-northeast-1"
PUBLIC_BUCKET = "manbo.chat"

# ============================================================================
# 图片处理参数（与 novel_backend 保持一致）
# ============================================================================
STANDARD_MAX_WIDTH = 800
STANDARD_QUALITY = 85
THUMB_MAX_WIDTH = 400
THUMB_QUALITY = 75


def _resize_and_compress(raw_bytes: bytes, max_width: int, quality: int) -> bytes:
    """Resize image proportionally (never upscale) and compress as WebP."""
    img = Image.open(io.BytesIO(raw_bytes))
    img = img.convert("RGB")

    w, h = img.size
    if w > max_width:
        ratio = max_width / w
        new_w = max_width
        new_h = int(h * ratio)
        img = img.resize((new_w, new_h), Image.LANCZOS)

    buf = io.BytesIO()
    img.save(buf, format="WEBP", quality=quality, optimize=True)
    return buf.getvalue()


def process_cover_image(raw_bytes: bytes) -> tuple[bytes, bytes]:
    """Process raw cover image bytes into standard and thumbnail versions."""
    standard = _resize_and_compress(raw_bytes, STANDARD_MAX_WIDTH, STANDARD_QUALITY)
    thumb = _resize_and_compress(raw_bytes, THUMB_MAX_WIDTH, THUMB_QUALITY)
    return standard, thumb


def get_s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def main():
    cover_dir = Path(__file__).parent / "deafult_cover"
    if not cover_dir.exists():
        print(f"错误: 目录不存在 {cover_dir}")
        sys.exit(1)

    # 收集所有 PNG 文件并按文件名排序
    png_files = sorted(cover_dir.glob("*.png"), key=lambda p: p.name)
    if not png_files:
        print("错误: deafult_cover/ 目录下没有找到 PNG 文件")
        sys.exit(1)

    print("=" * 60)
    print("  上传默认封面到 S3")
    print("=" * 60)
    print(f"  桶: {PUBLIC_BUCKET}")
    print(f"  区域: {AWS_REGION}")
    print(f"  找到 {len(png_files)} 张封面图片")
    print("=" * 60)

    s3 = get_s3_client()

    success = 0
    failed = 0

    for idx, png_path in enumerate(png_files, start=1):
        cover_name = f"deafult_cover_{idx}"
        standard_key = f"covers/{cover_name}.webp"
        thumb_key = f"covers/{cover_name}_thumb.webp"

        print(f"\n[{idx}/{len(png_files)}] {png_path.name}")
        print(f"  -> {standard_key}")
        print(f"  -> {thumb_key}")

        # 读取原始文件
        try:
            raw_bytes = png_path.read_bytes()
            original_size = len(raw_bytes)
        except Exception as e:
            print(f"  失败 (读取文件): {e}")
            failed += 1
            continue

        # 处理图片
        try:
            standard_bytes, thumb_bytes = process_cover_image(raw_bytes)
        except Exception as e:
            print(f"  失败 (图片处理): {e}")
            failed += 1
            continue

        # 上传标准版
        try:
            s3.put_object(
                Bucket=PUBLIC_BUCKET,
                Key=standard_key,
                Body=standard_bytes,
                ContentType="image/webp",
            )
        except Exception as e:
            print(f"  失败 (上传标准版): {e}")
            failed += 1
            continue

        # 上传缩略图
        try:
            s3.put_object(
                Bucket=PUBLIC_BUCKET,
                Key=thumb_key,
                Body=thumb_bytes,
                ContentType="image/webp",
            )
        except Exception as e:
            print(f"  失败 (上传缩略图): {e}")
            failed += 1
            continue

        print(
            f"  成功 (原始 {original_size:,}B -> "
            f"标准 {len(standard_bytes):,}B, "
            f"缩略 {len(thumb_bytes):,}B)"
        )
        success += 1

    print("\n" + "=" * 60)
    print("  上传汇总")
    print("=" * 60)
    print(f"  成功: {success}")
    print(f"  失败: {failed}")
    print(f"  总计: {len(png_files)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
