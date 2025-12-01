"""
crypto_utils.py - Stage99 用ユーティリティ

- QKD鍵(final_key.bin)の読み込み
- X25519 (楕円曲線DH) の鍵ペア生成と共有秘密計算
- QKD鍵 + ECDH共有秘密 からハイブリッドAES鍵をHKDFで導出
- AES-GCM での暗号化 / 復号
"""

import os
import base64
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519


# ========= QKD 鍵関連 =========

def load_qkd_key(path: str = "final_key.bin") -> bytes:
    """
    Stage98で生成した QKD 最終鍵をバイナリとして読み込む。
    そのまま AES鍵には使わず、「HKDFの salt」として利用する方針。
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"QKD鍵ファイル {path} が見つかりません。"
            " Stage98 から final_key.bin をコピーしましたか？"
        )
    with open(path, "rb") as f:
        key = f.read()
    if not key:
        raise ValueError(f"{path} が空です。QKD鍵の生成に失敗している可能性があります。")
    return key


# ========= X25519 (ECDH) 関連 =========

def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """
    X25519 の一時鍵ペアを生成する。
    戻り値:
        (private_key_obj, public_key_raw_bytes)
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def load_peer_public_key(raw_pub: bytes) -> x25519.X25519PublicKey:
    """
    生の 32バイト public key から X25519PublicKey オブジェクトを再構成。
    """
    if len(raw_pub) != 32:
        raise ValueError(f"X25519 公開鍵の長さが不正です: {len(raw_pub)} バイト (期待値: 32)")
    return x25519.X25519PublicKey.from_public_bytes(raw_pub)


def derive_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_key: x25519.X25519PublicKey,
) -> bytes:
    """
    ECDH (X25519) による共有秘密を計算。
    """
    return private_key.exchange(peer_public_key)


# ========= ハイブリッド鍵導出 (QKD + ECDH) =========

def hybrid_derive_aes_key(qkd_key: bytes, ecdh_secret: bytes, length: int = 32) -> bytes:
    """
    QKDの鍵 (final_key.bin) を HKDF の salt に、
    ECDH 共有秘密を input keying material にして AES鍵を導出。

    ・TLS1.3 のハイブリッド構成に近い考え方：
      - 「量子安全な QKD 鍵」と「従来の ECDH 秘密」を両方使うことで、
        どちらか一方が将来破られても、もう片方で安全性を補完する。
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,          # 32バイト → AES-256鍵
        salt=qkd_key,           # QKD鍵を salt として使う
        info=b"stage99-qkd-x25519-hybrid-key",
    )
    return hkdf.derive(ecdh_secret)


# ========= AES-GCM 関連 =========

def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes]:
    """
    AES-GCMで暗号化する。
    戻り値:
        (ciphertext_with_tag, nonce)
    ciphertext_with_tag は GCMタグを末尾に含んでいる。
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES鍵長が不正です: {len(key)} バイト (16/24/32 バイトのみ)")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM推奨 96ビット
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return ct, nonce


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = None) -> bytes:
    """
    AES-GCMで復号する。鍵・nonce・ciphertext/aad が合っていないと例外を投げる。
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ========= Base64 ヘルパー（JSONで渡しやすく） =========

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("ascii"))


# 依存している serialization を最後に import（循環回避のため）
from cryptography.hazmat.primitives import serialization  # noqa: E402
