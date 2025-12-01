# QS-TLS Stage104 — Mutual Authentication + AllowList + PQC + Hybrid Key Exchange + Directory Sync  
**Created by Motohiro Suzuki (c) 2024 — Released under the MIT License**

---

## 📌 概要
このプロジェクトは、量子時代に対応した安全通信プロトコル **QS-TLS** のプロトタイプ実装です。

QS-TLS は以下の技術を統合した、次世代の “量子安全ハイブリッド通信” を設計・実装しています：

- **QKD（量子鍵配送）**
- **X25519（ECDH）**
- **SPHINCS+（PQC署名）**
- **HKDF（鍵導出）**
- **AES-256-GCM（暗号化）**
- **Mutual Authentication（相互認証）**
- **AllowList（Zero-Trust 接続制御）**
- **Directory Sync（暗号化ディレクトリ同期）**

Stage104 は、QS-TLS の中核部分となる  
**安全なハンドシェイク + セッション鍵交換 + 相互認証 + 許可リスト制御 + ディレクトリ同期**  
を全て実装した段階です。

---

## 🔐 Stage104 で実装した内容（事実ベース）

### ✔ 1. **SPHINCS+（PQC）によるサーバー／クライアント相互認証**
- サーバー署名 → クライアントが検証  
- クライアント署名 → サーバーが検証  
- 量子攻撃にも耐性のある完全な Mutual Auth を構築

### ✔ 2. **AllowList によるクライアント制御（Zero Trust）**
- `server_allowlist.json` に登録された  
  `client_id + X25519 公開鍵` のみ接続を許可  
- 登録されていないクライアントはハンドシェイク前に拒否

### ✔ 3. **QKD × X25519 のハイブリッド鍵交換**
- QKD で生成された final_key.bin  
- X25519 の共有秘密  
→ HKDF による強力なミックス  
→ **AES-256-GCM のセッション鍵** を生成

### ✔ 4. **暗号化ディレクトリ同期（Dir Sync）**
- クライアントフォルダの内容をサーバーへ安全同期  
- 全て AES-GCM の暗号化レコードで送信

---

## 📁 フォルダ構成

```
stage104/
├── qs_tls_server.py
├── qs_tls_client.py
├── qs_tls_common.py
├── pq_sign.py
├── crypto_utils.py
├── server_allowlist.json
├── server_pq_keys/
└── client_keys/
```

---

## ▶ 実行方法

### ■ サーバー起動
```
python3 qs_tls_server.py
```

### ■ クライアント起動
```
python3 qs_tls_client.py
```

client01 / client02 どちらも以下の流れを実証済み：

- SPHINCS+署名の相互認証成功  
- AllowList による接続制御  
- ハイブリッド鍵交換完了  
- AES-GCM で暗号通信  
- ディレクトリ同期成功  

---

## 📜 License (MIT)

```
MIT License  
Copyright (c) 2024  
Motohiro Suzuki  

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.
```

---

## 📝 著作者の明記について

本プロトコル **QS-TLS の設計思想・仕様・コード** は  
Motohiro Suzuki による独自実装です。

MIT License により、利用・研究・改変・再配布は自由ですが、  
**著作権表記（Copyright © Motohiro Suzuki）は削除できません。**
