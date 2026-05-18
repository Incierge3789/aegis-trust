# Decision: Bitcoin OTS → PQC Migration Roadmap

**Date**: 2026-04-11
**Sprint**: S014 (Acceptance)
**Status**: Accepted
**Author**: incierge + claude-code
**Type**: policy_change

---

## Context

aegis-shield は Aegis 米軍規格 (Aegis 哲学 AO-001〜006) に準拠する Python SDK である。
S013 (v0.6.2) で導入した CI attestation infrastructure は、現状以下に依存している:

- **Hash algorithm**: SHA-256 (commit SHA + file hash + matrix result)
- **Timestamp anchor**: OpenTimestamps (Bitcoin blockchain への hash commitment)
- **Signature**: なし (file hash + Bitcoin Merkle proof のみ)

S014 Acceptance で incierge から「**Bitcoin チェーンは耐量子性 (CNSA 2.0 / NIST PQC) に対して妥当か?**」という指摘があり、現状の整理と移行ロードマップを記録する必要が生じた。

## Decision

**短期 (S014 内)**: 現状の Bitcoin OTS は維持する。OTS 検証ロジック自体は SHA-256 Merkle proof に依存するのみで、Grover アルゴリズム後も 128bit security を維持する。**ただし「PQ migration の代替」ではなく「Bitcoin タイムスタンプによる evidence anchoring」として境界を明示する**。

**中長期**: SHA-256 → SHA-3-512 化、Bitcoin → multi-anchor (Ethereum + 将来の PQC blockchain)、最終的に SLH-DSA / ML-DSA 署名追加を段階的に実施する。aegis-shield (SDK) と aegis-core (Rust gateway) のスコープは分離する。

## Quantum Vulnerability Analysis

### Bitcoin の暗号依存

| 用途 | アルゴリズム | 量子脆弱性 |
|---|---|---|
| アドレス署名 | ECDSA (secp256k1) | Shor で秒〜分で破られる |
| ブロックハッシュ | SHA-256 | Grover で 128bit security に低下 (実用安全) |
| Merkle tree | SHA-256 | 同上 |

### OpenTimestamps が使う暗号

OpenTimestamps が Bitcoin に書き込むのは **OP_RETURN にハッシュを埋める** だけ。署名検証ではなくブロック包含証明 (Merkle proof + block header) を使う。

**OTS 検証ロジック自体は ECDSA に依存しない**。SHA-256 Merkle proof と Bitcoin ブロックヘッダー (SHA-256) のみで検証可能。Grover の影響下でも 128bit security を維持する。

### Bitcoin チェーン全体の耐量子性

しかし問題は OTS 検証ロジック単体ではなく、Bitcoin ネットワーク全体の継続性にある:

- 量子コンピュータが実用化されると、Bitcoin そのものが攻撃される
- ECDSA 鍵から秘密鍵が逆算可能 → 大量盗難 → ハッシュレート崩壊 → チェーン再編成リスク
- 過去ブロックの **ハッシュは変わらない**が、ネットワーク自体が継続するか不明
- → 「Bitcoin チェーンが将来も検証可能な状態で存在し続ける」前提が崩れる可能性

### Q-day シナリオ別の影響

| シナリオ | 既存 OTS proof への影響 |
|---|---|
| Bitcoin が PQC fork (例: Lamport / SPHINCS+ 署名に移行) | 既存ブロックヘッダはそのまま、検証可能性維持 |
| Bitcoin が分裂 / 放棄される | 過去ブロックヘッダのアーカイブが残れば検証可、ただし第三者検証性は弱まる |
| 量子攻撃でチェーン再編成 (51% 攻撃) | 古いブロックは深さで守られる (現実的には 2009-2024 は不可逆)、新しい proof は危険 |

→ **2024年以前にスタンプされたものは比較的安全、未来のスタンプは Bitcoin の PQC 移行次第**。

## NIST PQC Standards (現状: 2026-04-11 時点)

### Final FIPS

| FIPS | アルゴリズム | 用途 | 公開日 | 直近の errata |
|---|---|---|---|---|
| **FIPS 203** | ML-KEM (Kyber) | Key encapsulation | 2024-08-13 | 2025-11-17 |
| **FIPS 204** | ML-DSA (Dilithium) | Digital signature | 2024-08-13 | 2026-02-23 |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based signature | 2024-08-13 | — |

### Additional KEM (4th round selection)

- **NIST IR 8545** (2025-03-11): **HQC** (Hamming Quasi-Cyclic) を additional KEM として選定。FIPS 化は将来の予定。

### Pending

- **FIPS 206 (FN-DSA / Falcon)**: 公開されていない (2026-04-11 時点)。**committed として扱わず pending として記録**。

### 一次ソース (URL/版/アクセス日固定)

- NIST PQC FIPS announcement (2024-08-13): https://www.nist.gov/news-events/news/2024/08/announcing-approval-three-federal-information-processing-standards-fips
- FIPS 203 (ML-KEM) final, errata 2025-11-17: https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA) final, errata 2026-02-23: https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA) final: https://csrc.nist.gov/pubs/fips/205/final
- NIST IR 8545 (HQC selected, 2025-03-11): https://csrc.nist.gov/pubs/ir/8545/final
- NSA CNSA 2.0 FAQ v2.1 (Dec 2024): https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF

(アクセス日: 2026-04-11、Plan Review v1〜v6 のレビュー検証で確認済み)

## CNSA 2.0 (NSA Commercial National Security Algorithm Suite)

CNSA 2.0 は **NSS (National Security Systems) 向け** の暗号要件であり、汎用商用ソフトウェアには直接適用されない。

### CNSA 2.0 タイムライン (FAQ v2.1, Dec 2024)

| 年 | マイルストーン |
|---|---|
| 2027 | CNSA 2.0 アルゴリズムへの初期移行開始 |
| 2030 | 既存 CNSA 1.0 アルゴリズムの段階的廃止 |
| 2031 | 主要 NSS で CNSA 2.0 完全運用 |
| 2035 | CNSA 1.0 アルゴリズム完全禁止 |

### aegis-shield (SDK) の立場

**aegis-shield 単体では CNSA 適合主張をしない**:
- CNSA 2.0 は NSS 向けで、汎用商用 SDK の適合要件ではない
- aegis-shield は Aegis 哲学 (米軍規格) を「設計思想」として参照するが、FIPS/CNSA 認証取得は現状計画していない
- 将来 aegis-core (Rust gateway) 側で CNSA 2.0 整合を進める場合、aegis-shield はそのクライアントとして追従する

## OpenTimestamps ≠ PQC Migration Substitute (重要)

**OTS は時刻証明 (Bitcoin タイムスタンプによる evidence anchoring) のみを提供する**。

| OTS が提供するもの | OTS が提供しないもの |
|---|---|
| ファイル/ハッシュが特定時刻に存在したことの証明 | 量子耐性の高い署名 |
| Bitcoin ブロックチェーンによる第三者検証 | TLS/通信路の暗号化 |
| Aegis 哲学 AO-004 (監査完全性) の補強 | NIST PQC FIPS 準拠 |

→ OTS を PQC 代替として誤解してはならない。OTS は **PQC 移行までの暫定的な evidence anchoring** として運用する (S014 Acceptance での incierge 指摘を反映)。

## Migration Roadmap

### 各バージョンと対象

| バージョン | 時期 | 対象 | アルゴリズム |
|---|---|---|---|
| **v0.6.3** | 2026-04 | attestation hash / OTS anchor | SHA-256 + Bitcoin OTS |
| **v0.6.4 (現在)** | S015 | attestation hash | **SHA-256 → SHA-3-512** (scripts/ci-attest.sh + Python hashlib.sha3_512、NIST FIPS 202 準拠) |
| **v0.8** | 2026 Q3 | attestation テンプレート | hash_alg field 追加、後方互換維持 |
| **v0.9** | 2026 Q3-Q4 | OTS calendar | **Bitcoin + Ethereum** multi-anchor (OpenTimestamps client は複数 calendar 対応) |
| **v1.0** | 2026 Q4 | OTS anchor | **+ PQC blockchain anchor** (QRL or successor) |
| **v1.x** | 2027+ | 署名追加 | **SLH-DSA (SPHINCS+) または ML-DSA (Dilithium)** で attestation 自体を署名 |
| **v2.x** | 2030 以降 | 全体 | aegis-core 側の CNSA 2.0 進捗に合わせて再評価 |

### 後方互換性

- 既存の Bitcoin OTS proof (`S013-v0.6.x.txt.ots`) は **2030 まで有効**として保持する
- v1.0 以降は新規 attestation のみ PQC anchor を必須化、既存は併存
- 検証ツールは旧 OTS proof と新 PQC proof の両方を検証可能とする (Aegis 監査ログの連続性 — AO-004)

## Boundary: aegis-shield (SDK) vs aegis-core (Rust)

| レイヤー | 現状 | PQC 移行責務 |
|---|---|---|
| **aegis-shield (Python SDK)** | attestation generation, OTS stamping | ハッシュアルゴリズム選択, OTS calendar 設定, 検証クライアント |
| **aegis-core (Rust gateway)** | Capsule encryption, audit log chain hash | 暗号プリミティブ (libsodium / RustCrypto / liboqs 等の選択), TLS 設定 |

両者は独立 git repo で管理されており、PQC 移行ロードマップも独立に進める。aegis-shield 側は SDK スコープ (attestation + OTS + 検証) のみを扱う。

## Consequences

### 短期 (S014 内、本 decision で完結)

- 現状の Bitcoin OTS 運用継続
- decision 記録 (本ファイル) で米軍規格との境界を明文化
- T-102/T-113 (post-gate launchd OTS watcher) は **「2030 までの暫定運用」** として動作
- aegis-shield README / SECURITY.md に「OTS は PQC 代替ではない」を追記する (S015 T-213 で実施済)

### 中期 (S015〜v0.9)

- SHA-256 → SHA-3-512 化 (S015 T-209 で v0.6.4 として実施済 — Python hashlib.sha3_512)
- multi-anchor 化の調査 (OpenTimestamps client の Ethereum support 確認)
- aegis-shield の依存関係に PQC ライブラリ (例: pyca/cryptography 47+ で ML-DSA サポート予定) の追加可否評価

### 長期 (v1.0〜)

- PQC blockchain anchor の選定 (QRL / Algorand / 候補ネットワークの安定性評価)
- SLH-DSA / ML-DSA 署名の attestation 実装
- aegis-core 側 CNSA 2.0 進捗とのアライメント

### リスク

- 2030 までに上記移行が間に合わない場合、既存 OTS proof の信頼性が低下する
- OpenTimestamps プロジェクト自体が PQC 対応しなかった場合、別の time-stamping 機構を選定する必要
- pyca/cryptography 等の PQC サポートが遅延した場合、独自実装が必要になる可能性

## Approval

- 2026-04-11: incierge 承認 (S014 Plan Review v6 GATE PASS で本 decision 含む計画全体を承認)
- Plan Review v1〜v6 で codex (`/cross-review` codex) と cursor-agent が一次ソースを照合し、NIST FIPS 203/204/205 / IR 8545 / CNSA 2.0 FAQ の事実整合性を確認済み (D-021〜D-026)

## References

- D-021 (Plan Review v1 GATE FAIL → v2)
- D-022 (Plan Review v2 GATE FAIL → v3)
- D-023 (Plan Review v3 GATE FAIL → v4)
- D-024 (Plan Review v4 GATE FAIL → v5)
- D-025 (Plan Review v5 split → v6)
- D-026 (Plan Review v6 PASS)
- D-027 (T-106 信頼境界 gate PASS)
