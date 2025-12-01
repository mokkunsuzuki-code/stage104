"""
Stage98: SPHINCS+ 署名テスト用モジュール
--------------------------------------
・ライブラリ: pyspx（SPHINCS+）
・パラメータ: SHAKE256-128f（pyspx.shake_128f を使用）
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Tuple

# ★ここが一番大事な修正ポイント★
#   間違い: from pyspx import shake256_128f as sphincs
#   正解  : import pyspx.shake_128f as sphincs
import pyspx.shake_128f as sphincs


# 鍵ファイルのパス
KEY_FILE = Path("pq_server_keys.json")


def ensure_server_keys() -> Tuple[bytes, bytes]:
    """
    サーバー用の SPHINCS+ 鍵ペアを用意する。

    - すでに pq_server_keys.json があれば、それを読み込む
    - なければ新しく鍵を生成して、pq_server_keys.json に保存する
    - 戻り値: (public_key, secret_key)
    """
    if KEY_FILE.exists():
        data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
        pk = bytes.fromhex(data["public_key"])
        sk = bytes.fromhex(data["secret_key"])
        return pk, sk

    # 新しく鍵を生成する
    seed = os.urandom(sphincs.crypto_sign_SEEDBYTES)
    pk, sk = sphincs.generate_keypair(seed)

    data = {
        "public_key": pk.hex(),
        "secret_key": sk.hex(),
    }
    KEY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return pk, sk


def load_public_key() -> bytes:
    """
    公開鍵だけを読み込む（クライアント側などで使用想定）
    """
    data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
    return bytes.fromhex(data["public_key"])


def sign_message(message: bytes, sk: bytes) -> bytes:
    """
    メッセージに SPHINCS+ 署名を付ける
    """
    return sphincs.sign(message, sk)


def verify_message(message: bytes, signature: bytes, pk: bytes) -> bool:
    """
    SPHINCS+ 署名を検証する。

    成功 → True, 失敗 → False
    """
    try:
        ok = sphincs.verify(message, signature, pk)
        return bool(ok)
    except Exception:
        return False


# このファイル単体で動かしたときのテストコード
if __name__ == "__main__":
    print("🔐 Stage98 SPHINCS+ テストを開始します。")

    # 1. サーバー用鍵を用意
    pk, sk = ensure_server_keys()
    print(f"✅ 公開鍵長さ: {len(pk)} バイト")
    print(f"✅ 秘密鍵長さ: {len(sk)} バイト")

    # 2. 正しいメッセージに署名
    msg = b"Stage98 SPHINCS+ test message"
    sig = sign_message(msg, sk)
    print(f"✅ 署名長さ: {len(sig)} バイト")

    # 3. 検証（正しいメッセージ）
    ok1 = verify_message(msg, sig, pk)
    print("✅ 正しいメッセージの検証結果:", ok1)

    # 4. 検証（改ざんメッセージ）
    tampered = b"Stage98 SPHINCS+ tampered"
    ok2 = verify_message(tampered, sig, pk)
    print("✅ 改ざんメッセージの検証結果:", ok2)

    print("🎉 Stage98 SPHINCS+ テスト完了。")
