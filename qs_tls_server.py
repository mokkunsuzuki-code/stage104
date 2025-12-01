"""
qs_tls_server.py - QS-TLS Server (Stage104)
QKD + X25519 ハイブリッド鍵交換 +
SPHINCS+ によるサーバー認証 ＋ クライアント認証（Mutual Auth） +
暗号化ディレクトリ同期 ＋ クライアントAllowlist

- クライアントは固定X25519鍵（クライアントIDごと）を使用
- サーバーは server_allowlist.json に登録された X25519 公開鍵のみ許可
"""

import os
import socket
import json
import base64
import hashlib
from typing import Any, Tuple, Optional, List, Dict

from crypto_utils import (
    load_qkd_key,
    generate_x25519_keypair,
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
import pq_sign


HOST = "127.0.0.1"
PORT = 50400  # Stage104 用ポート
ALLOWLIST_PATH = "server_allowlist.json"


# ======== PQ鍵ロード（dict / tuple 両対応） ========

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

    raise RuntimeError("pq_sign.ensure_server_keys() の戻り値形式が想定外です。")


def load_server_pq_keypair() -> Tuple[bytes, bytes]:
    """
    サーバー（SPHINCS+）で利用する鍵ペアをロード。
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

    print("[Server] 警告: pq_sign に verify 系関数が無いため検証をスキップします。")
    return True


# ======== Allowlist の管理 ========

def load_or_init_allowlist() -> Dict:
    """
    server_allowlist.json を読み込む。
    なければ空の allowlist を作成して保存。
    構造:
    {
      "allowed_clients": [
        {"client_id": "client01", "x25519_pub_hex": "abcd..."},
        ...
      ]
    }
    """
    if not os.path.exists(ALLOWLIST_PATH):
        data = {"allowed_clients": []}
        with open(ALLOWLIST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[Server] Allowlist を新規作成しました: {ALLOWLIST_PATH}")
        return data

    with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = {"allowed_clients": []}
    if "allowed_clients" not in data or not isinstance(data["allowed_clients"], list):
        data["allowed_clients"] = []
    return data


def save_allowlist(data: Dict) -> None:
    with open(ALLOWLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_client_allowed(allowlist: Dict, client_pub_hex: str) -> bool:
    for entry in allowlist.get("allowed_clients", []):
        if entry.get("x25519_pub_hex") == client_pub_hex:
            return True
    return False


def register_first_client_if_empty(allowlist: Dict, client_id: str, client_pub_hex: str) -> bool:
    """
    allowlist が空の場合のみ、最初のクライアントを自動登録する。
    戻り値: True = 登録した / すでに登録済み, False = 登録していない
    """
    clients: List[Dict] = allowlist.get("allowed_clients", [])
    if clients:
        return False  # 既に誰か登録済みなら何もしない

    entry = {
        "client_id": client_id,
        "x25519_pub_hex": client_pub_hex,
    }
    clients.append(entry)
    allowlist["allowed_clients"] = clients
    save_allowlist(allowlist)
    print(f"[Server] Allowlist が空だったため、最初のクライアントを自動登録しました:")
    print(f"         client_id={client_id}, x25519_pub_hex={client_pub_hex}")
    return True


# ======== メイン ========

def main():
    print("=== QS-TLS Server (Stage104: Mutual Auth + Allowlist + Dir Sync) ===")

    # QKD鍵ロード
    qkd_key = load_qkd_key("final_key.bin")
    print(f"[Server] QKD鍵読込み完了: {len(qkd_key)} バイト")

    # PQ署名鍵ロード（サーバー用）
    pq_public_key, pq_secret_key = load_server_pq_keypair()
    print(f"[Server] PQ公開鍵長: {len(pq_public_key)} バイト")

    # Allowlist ロード（クライアント専用 X25519 公開鍵リスト）
    allowlist = load_or_init_allowlist()
    print(f"[Server] Allowlist 内クライアント数: {len(allowlist.get('allowed_clients', []))}")

    # 受信先ルートディレクトリ
    recv_root = os.path.abspath("server_sync_root")
    os.makedirs(recv_root, exist_ok=True)
    print(f"[Server] 受信フォルダ: {recv_root}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Server] Listening on {HOST}:{PORT} ...")

        conn, addr = s.accept()
        with conn:
            print(f"[Server] クライアント接続: {addr}")

            # === Handshake: ClientHello ===
            rtype, payload = recv_record(conn)
            if rtype != RECORD_TYPE_HANDSHAKE:
                raise RuntimeError("[Server] 最初のメッセージが Handshake ではありません。")

            ch = json.loads(payload.decode("utf-8"))
            if ch.get("msg_type") != "client_hello":
                raise RuntimeError("[Server] client_hello が来ていません。")
            print("[Server] ClientHello 受信:", ch)

            # X25519 鍵ペア生成（サーバー側・エフェメラル）
            server_x_priv, server_x_pub = generate_x25519_keypair()

            # === Handshake: ServerHello ===
            sh = {
                "msg_type": "server_hello",
                "protocol": "QS-TLS-1.0",
                "group": "x25519",
            }
            send_record(conn, RECORD_TYPE_HANDSHAKE, json.dumps(sh).encode("utf-8"))
            print("[Server] ServerHello 送信")

            # === Handshake: ServerAuth (X25519 + PQ署名) ===
            if not hasattr(pq_sign, "sign_message"):
                raise RuntimeError("pq_sign.py に sign_message() がありません。")

            server_auth_payload = b"QS-TLS-SERVER-AUTH|" + server_x_pub
            server_signature = pq_sign.sign_message(server_auth_payload, pq_secret_key)  # type: ignore[attr-defined]

            sa = {
                "msg_type": "server_auth",
                "x25519_pub": server_x_pub.hex(),  # 16進文字列で送る
                "signature": server_signature.hex(),
            }
            send_record(conn, RECORD_TYPE_HANDSHAKE, json.dumps(sa).encode("utf-8"))
            print("[Server] ServerAuth 送信")

            # === Handshake: ClientAuth (相互認証 + Allowlist チェック) ===
            rtype, payload = recv_record(conn)
            if rtype != RECORD_TYPE_HANDSHAKE:
                raise RuntimeError("[Server] ClientAuth が Handshake レコードではありません。")

            ca = json.loads(payload.decode("utf-8"))
            if ca.get("msg_type") != "client_auth":
                raise RuntimeError("[Server] client_auth が来ていません。")

            client_id = ca.get("client_id", "unknown")
            client_x_pub_hex = ca["x25519_pub"]
            client_x_pub_bytes = bytes.fromhex(client_x_pub_hex)
            client_signature = bytes.fromhex(ca["signature"])

            client_auth_payload = (
                b"QS-TLS-CLIENT-AUTH|" + client_id.encode("utf-8") + b"|" + client_x_pub_bytes
            )

            # PQ署名検証（クライアント認証）
            if not verify_pq_signature(client_auth_payload, client_signature, pq_public_key):
                raise RuntimeError("[Server] クライアントPQ署名の検証に失敗しました。")
            print(f"[Server] クライアントPQ署名検証 OK（client_id={client_id}）")

            # Allowlist チェック
            # 1) Allowlist が空なら、自動で最初のクライアントを登録
            registered = register_first_client_if_empty(allowlist, client_id, client_x_pub_hex)
            if not registered:
                # 2) すでに Allowlist にクライアントがいる場合は、一致するかチェック
                if not is_client_allowed(allowlist, client_x_pub_hex):
                    print("[Server] このクライアントのX25519鍵は Allowlist に登録されていません。接続を拒否します。")
                    raise RuntimeError("クライアントが許可リストにありません。")

            print(f"[Server] Allowlist チェックOK（client_id={client_id}）")

            # 共有秘密 + ハイブリッドAES鍵
            client_x_pub = load_peer_public_key(client_x_pub_bytes)
            shared_secret = derive_shared_secret(server_x_priv, client_x_pub)
            aes_key = hybrid_derive_aes_key(qkd_key, shared_secret, length=32)
            print(f"[Server] ハイブリッドAES鍵 長さ: {len(aes_key)} バイト (AES-256)")
            print("[Server] Handshake 完了。アプリケーションデータ／同期を開始します。")

            current_key = aes_key

            # ディレクトリマニフェスト（オプション）
            current_manifest: Optional[dict] = None

            # ファイル受信状態
            file_out = None
            remaining_bytes = 0
            file_hash = None
            file_path = None
            expected_sha256: Optional[str] = None
            skip_current_file = False

            # === Application Data / Directory Sync ループ ===
            while True:
                rtype, payload = recv_record(conn)

                if rtype == RECORD_TYPE_APPLICATION_DATA:
                    # 通常テキストメッセージ
                    try:
                        plaintext = decrypt_app_data(current_key, payload)
                    except Exception as e:
                        print("[Server] テキスト復号に失敗:", e)
                        continue

                    text = plaintext.decode("utf-8", errors="replace")
                    print("[Server] 受信メッセージ:", text)

                    if text == "/quit":
                        print("[Server] クライアントからの終了要求。接続を閉じます。")
                        break

                    reply = f"[Server echo] {text}"
                    enc_payload = encrypt_app_data(current_key, reply.encode("utf-8"))
                    send_record(conn, RECORD_TYPE_APPLICATION_DATA, enc_payload)
                    print("[Server] エコーメッセージ送信")

                elif rtype == RECORD_TYPE_DIR_MANIFEST:
                    # ディレクトリマニフェスト受信
                    try:
                        manifest_plain = decrypt_app_data(current_key, payload)
                        current_manifest = json.loads(manifest_plain.decode("utf-8"))
                    except Exception as e:
                        print("[Server] マニフェスト復号/解析に失敗:", e)
                        current_manifest = None
                        continue

                    fc = current_manifest.get("file_count", "?")
                    print(f"[Server] ディレクトリマニフェスト受信: {fc} files")

                elif rtype == RECORD_TYPE_FILE_META:
                    # ファイルメタ情報（暗号化済み）を受信
                    try:
                        meta_plain = decrypt_app_data(current_key, payload)
                        meta = json.loads(meta_plain.decode("utf-8"))
                    except Exception as e:
                        print("[Server] ファイルメタ情報の復号/解析に失敗:", e)
                        continue

                    rel_path = meta.get("rel_path") or "received.bin"
                    filesize = int(meta.get("size") or 0)
                    expected_sha256 = meta.get("sha256")

                    # 保存先パスを決定
                    safe_rel = rel_path.replace("\\", "/")
                    dest_path = os.path.join(recv_root, safe_rel)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                    # すでに同じファイルがあり、サイズとハッシュが一致していればスキップ
                    if (
                        os.path.exists(dest_path)
                        and filesize > 0
                        and expected_sha256
                    ):
                        try:
                            existing_size = os.path.getsize(dest_path)
                            if existing_size == filesize:
                                h = hashlib.sha256()
                                with open(dest_path, "rb") as f:
                                    for chunk in iter(lambda: f.read(8192), b""):
                                        h.update(chunk)
                                if h.hexdigest() == expected_sha256:
                                    print(f"[Server] 既存ファイルと一致のためスキップ: {safe_rel}")
                                    file_out = None
                                    file_hash = None
                                    file_path = dest_path
                                    remaining_bytes = 0
                                    skip_current_file = True
                                    continue
                        except Exception as e:
                            print("[Server] 既存ファイルチェックでエラー:", e)

                    # 新規受信を開始
                    try:
                        file_out = open(dest_path, "wb")
                    except Exception as e:
                        print("[Server] ファイルオープンに失敗:", e)
                        file_out = None
                        file_hash = None
                        remaining_bytes = 0
                        skip_current_file = False
                        continue

                    remaining_bytes = filesize
                    file_hash = hashlib.sha256()
                    file_path = dest_path
                    skip_current_file = False
                    print(f"[Server] ファイル受信開始: {file_path} ({filesize} bytes)")

                elif rtype == RECORD_TYPE_FILE_CHUNK:
                    # ファイル本体チャンク
                    if skip_current_file:
                        continue

                    if file_out is None:
                        print("[Server] ファイルメタ情報なしで FILE_CHUNK を受信しました。無視します。")
                        continue

                    try:
                        chunk_plain = decrypt_app_data(current_key, payload)
                    except Exception as e:
                        print("[Server] ファイルチャンク復号に失敗:", e)
                        continue

                    file_out.write(chunk_plain)
                    if file_hash is not None:
                        file_hash.update(chunk_plain)

                    remaining_bytes -= len(chunk_plain)
                    if remaining_bytes > 0:
                        print(f"[Server] 受信中... 残り {remaining_bytes} bytes")
                    else:
                        file_out.close()
                        file_out = None
                        digest = file_hash.hexdigest() if file_hash is not None else "(no hash)"
                        print("[Server] ファイル受信完了:")
                        print(f"  Path   : {file_path}")
                        print(f"  SHA256 : {digest}")
                        if expected_sha256:
                            if digest == expected_sha256:
                                print("  [OK] 期待されたハッシュと一致しました。")
                            else:
                                print("  [NG] 期待されたハッシュと一致しません。")
                        remaining_bytes = 0
                        file_hash = None
                        file_path = None
                        expected_sha256 = None

                elif rtype == RECORD_TYPE_KEY_UPDATE:
                    # 鍵更新
                    current_key = update_application_key(current_key)
                    print("[Server] KeyUpdate 受信 → アプリケーション鍵を更新しました。")

                elif rtype == RECORD_TYPE_ALERT:
                    # 終了通知など（簡易実装）
                    if payload == b"close_notify":
                        print("[Server] close_notify 受信。接続を終了します。")
                        break
                    else:
                        print("[Server] Alert 受信:", payload)
                else:
                    print(f"[Server] 未知のレコードタイプを受信: {rtype}")


if __name__ == "__main__":
    main()
