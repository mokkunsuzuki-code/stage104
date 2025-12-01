"""
dump_pubkeys.py
client01 / client02 の X25519 公開鍵(hex) をきれいに表示する補助スクリプト
"""

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def dump_client_pub(client_id: str) -> None:
    pem_path = Path("client_keys") / f"{client_id}_x25519.pem"
    if not pem_path.exists():
        print(f"[ERROR] {pem_path} がありません。先に qs_tls_client.py を一度実行して鍵を作ってください（client_id={client_id}）。")
        return

    with pem_path.open("rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not isinstance(private_key, x25519.X25519PrivateKey):
        print(f"[ERROR] {pem_path} は X25519 秘密鍵ではありません。")
        return

    public_key = private_key.public_key()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    hexstr = raw.hex()

    print(f"== {client_id} 公開鍵 hex ({len(raw)} bytes) ==")
    # 見やすいように 32文字ごとに改行
    for i in range(0, len(hexstr), 32):
        print(hexstr[i : i + 32])
    print()


def main() -> None:
    for cid in ("client01", "client02"):
        dump_client_pub(cid)


if __name__ == "__main__":
    main()

