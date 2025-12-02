QS-TLS Stage105 — Quantum-Secure Transport with Realtime Encrypted Messaging
© 2025 Motohiro Suzuki — Licensed under MIT License

このリポジトリは、量子安全通信プロトコル「QS-TLS」の Stage105（リアルタイム暗号チャット） を実装したものです。
MIT ライセンスのため、商用利用・改変・再配布すべて自由ですが、著作権表記（© Motohiro Suzuki）は保持されます。

📝 概要（Overview）

Stage105 では、QS-TLS のアプリケーション層の中核である
「暗号化メッセージ送受信（Application Data Record）」を実装 しました。

本ステージの主な達成点

AES-256-GCM で暗号化されたメッセージのリアルタイム送受信

ACK レコード（ack0〜ackN）の実装

Quit レコードでのクリーンな接続終了

クライアント・サーバー双方向の暗号チャット

Stage104 の「Mutual Authentication + AllowList + Directory Sync」と完全互換

🔐 技術内容（Technical Details）
1. 暗号スイート
項目	内容
量子鍵配送（QKD）	final_key.bin（766 byte）
ECDH	X25519
PQC署名	SPHINCS+
ハイブリッド鍵導出	HKDF(QKD鍵 + ECDH秘密)
通信暗号	AES-256-GCM
2. レコードタイプ（独自仕様）
Record Type	説明
APPLICATION_DATA	暗号化されたメッセージ
ACK	受信確認
QUIT	セッション終了
3. Stage105 で追加された機能
✔ 双方向リアルタイム暗号チャット
Client → Server → Client


の暗号化されたメッセージ交換。

✔ ACK レスポンス

メッセージごとに
ack0, ack1, ack2 …
と自動で応答。

✔ QUIT レコード

安全に接続を終了。

✔ Thread による同時処理

受信スレッド

送信スレッド
の同時動作が可能。

📂 ファイル構成（Structure）
stage105/
 ├── qs_tls_client.py      # クライアント（暗号チャット）
 ├── qs_tls_server.py      # サーバー（複数クライアント待受け）
 ├── qs_tls_common.py      # 共通レコード処理 / 暗号API
 ├── crypto_utils.py       # ハイブリッド鍵導出 / AES-GCM暗号化
 ├── pq_sign.py            # SPHINCS+ 署名・検証
 ├── manifest_utils.py     # ディレクトリ同期
 └── server_allowlist.json # 許可クライアント（MutualAuth）

▶ 動作方法（Run）
1. サーバー起動
cd stage105
python3 qs_tls_server.py

2. クライアント起動
cd stage105
python3 qs_tls_client.py


起動後：

クライアントIDを入力してください： client01

3. チャット入力
送信メッセージ入力（/quitで終了）> こんにちは


ACK例：

[Client] ACK 受信：ack2
