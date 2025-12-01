"""
qs_tls_common.py - QS-TLS (Quantum-Secure Mini TLS) 共通ユーティリティ

Stage102/103:
  - レコードタイプにディレクトリ同期用を追加
  - アプリケーションデータ / ファイルチャンク / マニフェストの暗号化を共通化
"""

import socket
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from crypto_utils import encrypt_aes_gcm, decrypt_aes_gcm, b64e, b64d


# ======== レコードタイプ定義（TLS風） ========

RECORD_TYPE_ALERT = 21            # 警告 / 終了
RECORD_TYPE_HANDSHAKE = 22        # ハンドシェイクメッセージ（JSON）
RECORD_TYPE_APPLICATION_DATA = 23 # アプリケーションデータ（暗号化テキスト）
RECORD_TYPE_KEY_UPDATE = 24       # 鍵更新通知
RECORD_TYPE_FILE_META = 25        # ファイル情報（ファイル名・サイズ・ハッシュなど）
RECORD_TYPE_FILE_CHUNK = 26       # ファイル本体データ（分割チャンク）
RECORD_TYPE_DIR_MANIFEST = 27     # ディレクトリ全体のマニフェスト（JSON）


# ======== レコード送受信 ========

def send_record(conn: socket.socket, record_type: int, payload: bytes) -> None:
    """
    Record Header (3 bytes) + Payload を送信
    - record_type: 1 byte
    - length: 2 bytes (big endian)
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    if not (0 <= record_type <= 255):
        raise ValueError("record_type must fit in 1 byte")

    length = len(payload)
    if length > 0xFFFF:
        raise ValueError("payload too long (max 65535 bytes)")

    header = bytes([record_type]) + length.to_bytes(2, "big")
    conn.sendall(header + payload)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("接続が途中で切断されました。")
        buf += chunk
    return buf


def recv_record(conn: socket.socket) -> Tuple[int, bytes]:
    """
    1レコードを受信して (record_type, payload_bytes) を返す
    """
    header = _recv_exact(conn, 3)
    record_type = header[0]
    length = int.from_bytes(header[1:3], "big")
    payload = _recv_exact(conn, length)
    return record_type, payload


# ======== アプリケーションデータ／ファイルチャンク／マニフェストの暗号化・復号 ========

def encrypt_app_data(aes_key: bytes, plaintext: bytes) -> bytes:
    """
    データを AES-GCM で暗号化し、JSONバイト列として返す。

    JSON構造:
      {
        "nonce": "<base64>",
        "ciphertext": "<base64>"
      }

    アプリケーションデータ／ファイルチャンク／マニフェストなどに共通利用。
    """
    import json

    ct, nonce = encrypt_aes_gcm(aes_key, plaintext, aad=None)
    obj = {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
    }
    return json.dumps(obj).encode("utf-8")


def decrypt_app_data(aes_key: bytes, payload: bytes) -> bytes:
    """
    encrypt_app_data で作った JSON ペイロードを復号して平文バイト列を返す。
    """
    import json

    obj = json.loads(payload.decode("utf-8"))
    nonce = b64d(obj["nonce"])
    ct = b64d(obj["ciphertext"])
    return decrypt_aes_gcm(aes_key, ct, nonce, aad=None)


# ======== 鍵更新 (KeyUpdate) ========

def update_application_key(current_key: bytes) -> bytes:
    """
    現在のアプリケーション鍵から、新しい鍵を導出する。
    - TLS1.3 の KeyUpdate に相当するイメージ。
    - 実装: HKDF(salt=current_key, ikm="key-update") → new_key
    """
    if not current_key:
        raise ValueError("current_key is empty")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=len(current_key),
        salt=current_key,
        info=b"qs-tls-1.0 key update",
    )
    new_key = hkdf.derive(b"key-update")
    return new_key
