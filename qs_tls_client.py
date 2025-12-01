"""
qs_tls_client.py - QS-TLS Client (Stage104)
QKD + X25519 ハイブリッド鍵交換 +
SPHINCS+ によるサーバー認証 ＋ クライアント認証（Mutual Auth） +
暗号化ファイル送信 & ディレクトリ同期

- クライアントIDごとに固定X25519鍵を生成＆保存
- サーバー側の Allowlist に登録されたX25519公開鍵だけ接続可能
"""

import os
import socket
import json
import base64
from typing import Any, Tuple

from crypto_utils import (
    load_qkd_key,
    load_peer_public_key,
    derive_shared_secret,
    hybrid_derive_aes_key,
)
from qs_tls_common import (
    RECORD_TYPE_HANDSHAKE,
    RECORD_TYPE_APPLICATION_DATA,
    RECORD_TYPE_KEY_UPDATE,
    RECORD_TYPE_ALERT,
    RECORD_TYPE_FILE_META,
    RECORD_TYPE_FILE_CHUNK,
    RECORD_TYPE_DIR_MANIFEST,
    send_record,
    recv_record,
    encrypt_app_data,
    decrypt_app_data,
    update_application_key,
)
from manifest_utils import build_manifest
import pq_sign

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


HOST = "127.0.0.1"
PORT = 50400  # サーバーと合わせる
CLIENT_KEYS_DIR = "client_keys"


# ======== PQ 鍵ペアロード（dict / tuple 両対応） ========

def _normalize_pq_keys(info: Any) -> Tuple[bytes, bytes]:
    """
    pq_sign の戻り値を (public_key_bytes, secret_key_bytes) に正規化
    """
    def _to_bytes(x):
        if isinstance(x, str):
            return base64.b64decode(x)
        if isinstance(x, (bytes, bytearray)):
            return bytes(x)
        raise RuntimeError("pq_sign の鍵形式が予期しない型です。")

    if isinstance(info, dict):
        pk_b64 = info.get("public_key_b64") or info.get("public_key")
        sk_b64 = (
            info.get("private_key_b64")
            or info.get("secret_key_b64")
            or info.get("private_key")
            or info.get("secret_key")
        )
        if not pk_b64 or not sk_b64:
            raise RuntimeError("pq_sign の dict に public_key / private_key が含まれていません。")

        pk = _to_bytes(pk_b64)
        sk = _to_bytes(sk_b64)
        return pk, sk

    if isinstance(info, (tuple, list)) and len(info) >= 2:
        pk = _to_bytes(info[0])
        sk = _to_bytes(info[1])
        return pk, sk

    raise RuntimeError("pq_sign.ensure_server_keys() の戻り値が想定外です。")


def load_pq_keypair() -> Tuple[bytes, bytes]:
    """
    SPHINCS+ 鍵ペアをロード。
    ※ Stage98〜103 と同じ pq_sign の鍵をそのまま使用。
    """
    if hasattr(pq_sign, "ensure_server_keys"):
        info = pq_sign.ensure_server_keys()
    elif hasattr(pq_sign, "generate_or_load_server_keys"):
        info = pq_sign.generate_or_load_server_keys()
    else:
        raise RuntimeError(
            "pq_sign.py に ensure_server_keys / generate_or_load_server_keys が見つかりません。"
        )
    return _normalize_pq_keys(info)


def verify_pq_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    pq_sign 側の verify_* 系APIのどれかを使って署名検証を行う。
    """
    if hasattr(pq_sign, "verify_signature"):
        return pq_sign.verify_signature(message, signature, public_key)  # type: ignore[attr-defined]
    if hasattr(pq_sign, "verify_message"):
        return pq_sign.verify_message(message, signature, public_key)  # type: ignore[attr-defined]
    if hasattr(pq_sign, "verify"):
        return pq_sign.verify(message, signature, public_key)  # type: ignore[attr-defined]

    print("[Client] 警告: pq_sign に verify 系関数が無いため検証をスキップします。")
    return True


# ======== クライアント用 固定X25519鍵 管理 ========

def load_or_create_client_x25519(client_id: str) -> Tuple[X25519PrivateKey, bytes]:
    """
    クライアントIDごとの固定X25519秘密鍵を生成・ロードする。
    秘密鍵は PEM として client_keys/{client_id}_x25519.pem に保存。
    戻り値:
      (X25519PrivateKeyオブジェクト, 公開鍵(32バイト))
    """
    os.makedirs(CLIENT_KEYS_DIR, exist_ok=True)
    key_path = os.path.join(CLIENT_KEYS_DIR, f"{client_id}_x25519.pem")

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            priv = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        if not isinstance(priv, X25519PrivateKey):
            raise RuntimeError("保存されている鍵が X25519PrivateKey ではありません。")
    else:
        priv = X25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(pem)
        print(f"[Client] 新しいX25519鍵を生成しました: {key_path}")

    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


# ======== 単一ファイル送信 ========

def send_encrypted_file(sock: socket.socket, aes_key: bytes) -> None:
    """
    ユーザーからファイルパスを聞き、QS-TLS 上で暗号化して送信する。
    """
    path = input("送信したいファイルのパスを入力してください: ").strip()
    if not path:
        print("[Client] ファイルパスが空です。中止します。")
        return
    if not os.path.isfile(path):
        print(f"[Client] ファイルが見つかりません: {path}")
        return

    filesize = os.path.getsize(path)
    filename = os.path.basename(path)

    meta = {
        "msg_type": "file_meta",
        "rel_path": filename,
        "size": filesize,
        "sha256": None,
    }
    meta_plain = json.dumps(meta).encode("utf-8")
    enc_meta = encrypt_app_data(aes_key, meta_plain)
    send_record(sock, RECORD_TYPE_FILE_META, enc_meta)
    print(f"[Client] ファイルメタ情報送信: {filename} ({filesize} bytes)")

    chunk_size = 4096
    sent_bytes = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            enc_chunk = encrypt_app_data(aes_key, chunk)
            send_record(sock, RECORD_TYPE_FILE_CHUNK, enc_chunk)
            sent_bytes += len(chunk)
            print(f"[Client] 送信中... {sent_bytes}/{filesize} bytes", end="\r")

    print()
    print(f"[Client] ファイル送信完了: {filename}")


# ======== ディレクトリ同期 ========

def sync_directory(sock: socket.socket, aes_key: bytes) -> None:
    """
    指定ディレクトリ以下のファイルをマニフェストにまとめ、
    QS-TLS 上で暗号化して一括送信する。
    """
    root = input("同期したいディレクトリのパスを入力してください: ").strip()
    if not root:
        print("[Client] ディレクトリパスが空です。中止します。")
        return
    if not os.path.isdir(root):
        print(f"[Client] ディレクトリが見つかりません: {root}")
        return

    print("[Client] マニフェスト作成中...")
    manifest = build_manifest(root)
    file_count = manifest.get("file_count", 0)
    print(f"[Client] マニフェスト作成完了: {file_count} files")

    # 1) マニフェストを送信
    manifest_plain = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    enc_manifest = encrypt_app_data(aes_key, manifest_plain)
    send_record(sock, RECORD_TYPE_DIR_MANIFEST, enc_manifest)
    print("[Client] ディレクトリマニフェスト送信")

    # 2) 各ファイルを順番に送信
    files = manifest.get("files", [])
    for idx, info in enumerate(files, start=1):
        rel_path = info["rel_path"]
        size = int(info["size"])
        sha256 = info["sha256"]

        abs_path = os.path.join(root, rel_path)
        print(f"[Client] [{idx}/{file_count}] 送信開始: {rel_path} ({size} bytes)")

        meta = {
            "rel_path": rel_path,
            "size": size,
            "sha256": sha256,
        }
        meta_plain = json.dumps(meta).encode("utf-8")
        enc_meta = encrypt_app_data(aes_key, meta_plain)
        send_record(sock, RECORD_TYPE_FILE_META, enc_meta)

        chunk_size = 4096
        sent_bytes = 0
        with open(abs_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                enc_chunk = encrypt_app_data(aes_key, chunk)
                send_record(sock, RECORD_TYPE_FILE_CHUNK, enc_chunk)
                sent_bytes += len(chunk)
                print(
                    f"[Client]  送信中... {sent_bytes}/{size} bytes",
                    end="\r",
                )

        print()
        print(f"[Client]  完了: {rel_path}")

    print("[Client] ディレクトリ同期完了。")


# ======== メイン ========

def main():
    print("=== QS-TLS Client (Stage104: Mutual Auth + Allowlist + Dir Sync) ===")

    # クライアントIDを入力（例: client01）
    client_id = input("クライアントIDを入力してください（例: client01）: ").strip()
    if not client_id:
        client_id = "client01"
    print(f"[Client] 使用クライアントID: {client_id}")

    # QKD鍵ロード
    qkd_key = load_qkd_key("final_key.bin")
    print(f"[Client] QKD鍵読込み完了: {len(qkd_key)} バイト")

    # PQ 鍵ペアロード（サーバー／クライアント共通のSPHINCS+鍵）
    pq_public_key, pq_secret_key = load_pq_keypair()
    print(f"[Client] PQ公開鍵 長さ: {len(pq_public_key)} バイト")

    # 固定X25519鍵（クライアントIDごと）
    client_x_priv, client_x_pub_bytes = load_or_create_client_x25519(client_id)
    client_x_pub_hex = client_x_pub_bytes.hex()
    print(f"[Client] X25519 公開鍵(hex): {client_x_pub_hex[:16]}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[Client] 接続: {HOST}:{PORT}")

        # === Handshake: ClientHello ===
        ch = {
            "msg_type": "client_hello",
            "protocol": "QS-TLS-1.0",
            "client_name": f"Stage104-Client-{client_id}",
            "support_groups": ["x25519"],
        }
        send_record(s, RECORD_TYPE_HANDSHAKE, json.dumps(ch).encode("utf-8"))
        print("[Client] ClientHello 送信")

        # === Handshake: ServerHello ===
        rtype, payload = recv_record(s)
        if rtype != RECORD_TYPE_HANDSHAKE:
            raise RuntimeError("[Client] ServerHello が Handshake レコードではありません。")
        sh = json.loads(payload.decode("utf-8"))
        if sh.get("msg_type") != "server_hello":
            raise RuntimeError("[Client] server_hello が来ていません。")
        print("[Client] ServerHello 受信:", sh)

        # === Handshake: ServerAuth (PQ署名検証) ===
        rtype, payload = recv_record(s)
        if rtype != RECORD_TYPE_HANDSHAKE:
            raise RuntimeError("[Client] ServerAuth が Handshake レコードではありません。")
        sa = json.loads(payload.decode("utf-8"))
        if sa.get("msg_type") != "server_auth":
            raise RuntimeError("[Client] server_auth が来ていません。")

        server_x_pub_bytes = bytes.fromhex(sa["x25519_pub"])
        server_signature = bytes.fromhex(sa["signature"])
        server_auth_payload = b"QS-TLS-SERVER-AUTH|" + server_x_pub_bytes

        if not verify_pq_signature(server_auth_payload, server_signature, pq_public_key):
            raise RuntimeError("[Client] サーバーPQ署名の検証に失敗しました。")
        print("[Client] サーバーPQ署名検証 OK（サーバー認証完了）")

        # === Handshake: ClientAuth (自分も署名して送信) ===
        if not hasattr(pq_sign, "sign_message"):
            raise RuntimeError("pq_sign.py に sign_message() がありません。")

        client_auth_payload = (
            b"QS-TLS-CLIENT-AUTH|" + client_id.encode("utf-8") + b"|" + client_x_pub_bytes
        )
        client_signature = pq_sign.sign_message(client_auth_payload, pq_secret_key)  # type: ignore[attr-defined]

        ca = {
            "msg_type": "client_auth",
            "client_id": client_id,
            "x25519_pub": client_x_pub_hex,
            "signature": client_signature.hex(),
        }
        send_record(s, RECORD_TYPE_HANDSHAKE, json.dumps(ca).encode("utf-8"))
        print("[Client] ClientAuth 送信（クライアント認証）")

        # 共有秘密 + ハイブリッドAES鍵
        server_x_pub = load_peer_public_key(server_x_pub_bytes)
        shared_secret = derive_shared_secret(client_x_priv, server_x_pub)
        aes_key = hybrid_derive_aes_key(qkd_key, shared_secret, length=32)
        current_key = aes_key
        print(f"[Client] ハイブリッドAES鍵 長さ: {len(aes_key)} バイト (AES-256)")
        print("[Client] Handshake 完了。メッセージ／ファイル／ディレクトリ同期を開始します。")

        # === Application Data / Directory Sync ループ ===
        while True:
            try:
                text = input(
                    "\n送信メッセージを入力 "
                    "(/keyupdate /sendfile /syncdir /quit も可): "
                ).strip()
            except EOFError:
                text = "/quit"

            if text == "/quit":
                # まず暗号化アプリケーションデータとして送る
                payload = encrypt_app_data(current_key, text.encode("utf-8"))
                send_record(s, RECORD_TYPE_APPLICATION_DATA, payload)
                # その後、Alert(close_notify) を送信
                send_record(s, RECORD_TYPE_ALERT, b"close_notify")
                print("[Client] /quit を送信しました。")
                break

            elif text == "/keyupdate":
                # KeyUpdate レコードを送信し、その後自分の鍵を更新
                send_record(s, RECORD_TYPE_KEY_UPDATE, b"")
                current_key = update_application_key(current_key)
                print("[Client] KeyUpdate を送信し、ローカル鍵を更新しました。")
                continue

            elif text == "/sendfile":
                # 単一ファイル暗号送信
                send_encrypted_file(s, current_key)
                continue

            elif text == "/syncdir":
                # ディレクトリ同期
                sync_directory(s, current_key)
                continue

            else:
                # 通常メッセージ
                payload = encrypt_app_data(current_key, text.encode("utf-8"))
                send_record(s, RECORD_TYPE_APPLICATION_DATA, payload)
                print("[Client] アプリケーションデータ送信:", text)

                # サーバーからのエコーメッセージ受信
                rtype, payload = recv_record(s)
                if rtype == RECORD_TYPE_APPLICATION_DATA:
                    try:
                        reply_plain = decrypt_app_data(current_key, payload)
                        print("[Client] サーバーからの復号済みメッセージ:")
                        print("  ", reply_plain.decode("utf-8", errors="replace"))
                    except Exception as e:
                        print("[Client] サーバーメッセージの復号に失敗:", e)
                elif rtype == RECORD_TYPE_ALERT and payload == b"close_notify":
                    print("[Client] サーバーから close_notify。接続終了。")
                    break
                else:
                    print(f"[Client] 想定外のレコードタイプ受信: {rtype}")


if __name__ == "__main__":
    main()
