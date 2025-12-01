"""
manifest_utils.py - Stage102 用ディレクトリマニフェストユーティリティ

指定ディレクトリ以下のファイル一覧・サイズ・SHA256 を集めて
マニフェスト(JSON相当の dict) を作成する。
"""

import os
import hashlib
from typing import Dict, List


def compute_sha256(path: str, chunk_size: int = 8192) -> str:
    """ファイルの SHA256 ハッシュを 16進文字列で返す。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root_dir: str) -> Dict:
    """
    ディレクトリ root_dir 以下を再帰的に走査し、
    相対パス・サイズ・SHA256 を記録したマニフェストを返す。
    """
    root_dir = os.path.abspath(root_dir)
    files: List[Dict] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, root_dir)
            rel_path = rel_path.replace("\\", "/")  # Windows 対策（見た目を統一）

            size = os.path.getsize(full_path)
            sha256 = compute_sha256(full_path)

            files.append(
                {
                    "rel_path": rel_path,
                    "size": size,
                    "sha256": sha256,
                }
            )

    manifest: Dict = {
        "root": root_dir,
        "file_count": len(files),
        "files": files,
    }
    return manifest
