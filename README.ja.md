# ad-lite-lab — シングルコンテナ Active Directory 演習環境

[English](README.md) | **日本語** | [简体中文](README.zh.md)

コンパクトな Active Directory 攻撃演習環境。Samba 4.24 のドメインコントローラ 1 台
(`dc01.lite.corp`、ドメイン `LITE.CORP`) を Docker コンテナ 1 つに収め、ユーザー・グループ・
サービスアカウント・委任・意図的に設計された ACL チェーンをシード済み。フラグ 2 個、
想定解ルート 1 本、Windows ライセンス不要、メモリ約 1.5 GB。

マルチ VM ラボでは高コストになる AD 実務スキル — 匿名面の列挙、辞書攻撃で到達可能な
入口資格情報、ACL レコン、グループメンバシップ悪用、通常バインドでは見えないデータの読取 —
の習得に特化しています。想定解は [docs/SOLUTION.md](docs/SOLUTION.md) に記載
(解き終わるまで開かないこと)。

## 開発動機

GOAD 系のフルレンジは Windows VM 3 台以上と 12〜18 GB の RAM を必要とし、
Apple Silicon では実質動作しません。`ad-lite-lab` は *ID 攻撃面*
(列挙 → 侵入 → ACL 悪用 → 複製スコープのデータ) を ARM64 対応コンテナ 1 つに集約し、
全ステップをブラインド状態でも解ける水準に保っています。本ラボは AI エージェントによる
攻撃パイプラインで構築・較正されました(下記の[実戦較正](#実戦較正))。
つまり、あなたが突き当たる壁はまず機械が突き当たり、手がかりは全て到達可能性が
検証済みです。

## 前提条件

- Docker (Engine / OrbStack / Docker Desktop) または compose 対応 Podman
- DC コンテナ用に 2 vCPU / 2 GB RAM の空き
- コンテナの公開ポートに到達できる攻撃用マシン (Kali 推奨。`scripts/` は
  Debian 系 + sudo 前提)
- 攻撃マシンと DC の時刻差 5 分以内 (Kerberos の基本)

## クイックスタート

```bash
git clone https://github.com/tani2shell/ad-lite-lab.git
cd ad-lite-lab

# 1. ワンショット起動: secrets.env とフラグ生成 → ドメイン構築 → DC 起動 →
#    LDAP ソケット待ち → アカウント/グループ/ACL/フラグのシード
./forge_samba.sh provision        # 初回は数分

# 2. DC の生存確認
./forge_samba.sh status
./forge_samba.sh logs 50

# 3. (攻撃マシン側) ホスト名前解決と Kerberos リアムの設定
sudo bash scripts/kali_wiring.sh  # /etc/hosts と /etc/krb5.conf.d を登録
```

DC は AD 標準ポートに加え、ミラーポート `1088` (Kerberos) と `1445` (SMB) でも
公開されています。macOS ではホスト OS が 88/445 を先に占有するため
[プラットフォームマトリクス](#プラットフォームマトリクス)を参照。既定の攻撃姿勢:

| 項目 | 値 |
|---|---|
| ドメイン | `LITE.CORP` (NetBIOS: `LITE`) |
| DC ホスト名 | `dc01.lite.corp` |
| `-dc-ip` | 攻撃マシンから見た Docker ホストアドレス (マトリクス参照) |
| SMB ポート | Linux では `445`、macOS では `--port 1445` (netexec は `--port` を使用。**`-p` ではない**) |

運用コマンド:

```bash
./scripts/acceptance_battery.sh   # 7 項目の健全性バッテリー (攻撃マシンから実行)
bash scripts/reseed.sh            # 冪等な再シード (フラグ値は不変)
./forge_samba.sh reset            # 全消去 → 再構築 → 再シード
./forge_samba.sh down             # 停止 (ボリュームは保持)
```

### フラグと資格情報のカスタマイズ

初回 provision で生成される `secrets.env` (コミットしない) にドメイン管理者・
サービス資格情報・フラグ 2 個の値が入ります。書式は `secrets.env.example` 参照。
編集後は `scripts/reseed.sh` で再適用。フラグ値は採点側用に
`flags/local.flag` / `flags/proof.flag` に置かれ、ソルバーはディスクではなく
AD から読み出します。

## 中身 (ネタバレなし)

- DC 1 台、公開フラグ 2 個、想定チェーン 1 本、デコイ多数
- SPN・委任フラグ・階層グループ・カスタムスキーマ属性など、現実的な AD の癖をシード
- 辞書スプレーでの侵入が再現可能になるよう調整したドメインポリシー
- `docs/SOLUTION.md` — 想定ルート、代替ルート、そして「設計上の壁」と
  「Samba と Windows の実装差による壁」の区別

## 実戦較正

以下の数値は、開発者側の AI 攻撃パイプラインによる本リファレンス環境での実測 —
**Apple M5 Ultra、ローカル oMLX Qwen3.8-Flash-Next、OrbStack Kali (ARM64) 攻撃マシン**。
モデルやハードが変われば速くも遅くもなります。一つの較正データ点としてお受け取りください。

- 想定解帯 (情報を得たエージェント): **20〜40 分**
- 完全ブラインド解読 (事前情報ゼロの攻撃者): **2/2 フラグ**、実時間 **約 50 分** —
  辞書スプレーで入口 → ACL 昇格チェーン → 独自スキーマ属性からフラグ読出 (実走 1 本)
- 入口資格情報への到達: 単一アカウントのブラインドスプレーで **19,646
  リクエスト** (入口パスワードは主要 top-50k 辞書のバイト単位完全一致
  ランク 19646 位、約 130 req/s)。6 アカウント横断では約 11.8 万リクエストで初達
- 列挙完全性: 250 万リクエストのブラインド実行で有効プリンシパル全集を
  3 波の独立列挙で見落としなく網羅

## プラットフォームマトリクス

| ホスト | 攻撃姿勢 | 備考 |
|---|---|---|
| Linux (ネイティブ Docker) | 標準ポート 88/445/389… へ直接接続 | ホスト IP へ向ける。SMB はホストの smbd が空いていれば 445 で可 |
| macOS (OrbStack / Docker Desktop) | ミラーポート: Kerberos `1088` / SMB `1445` | macOS のファイル共有が Docker より先に :88/:445 を黙って占有する。`scripts/kali_kdc_relay.sh` + `scripts/kali_nft_persist.sh` で systemd 永続の `:88 → :1888 → host:1088` リダイレクトをインストールすれば AD ツールは既定姿勢のまま。SMB ツールは `--port 1445` 必須。Kerberos の結果を信じる前に `acceptance_battery.sh` の check 0 を通すこと |
| WSL2 (WSL2 内 Docker) | WSL2 ネットワークで公開できていれば Linux 扱い | Windows ホスト側も 445 を占有しがち。迷ったら 1445 ミラー + Kali スクリプト |
| Windows (Docker Desktop) | macOS と同様にミラーポート | ホスト smbd が 445 を占有。停止するか 1445 を使用 |
| CPU アーキテクチャ | arm64 / amd64 両対応 | 基底イメージはマルチアーキ。本ラボは arm64 で構築・較正 |

## 既知の環境クセ (高い授業料の末の記録 — 二度払い不要)

- **netexec の `-p` はパスワードでありポートではない。** ポートは `--port 1445`。
  `-p 1445` を渡すと「パスワード」がポートに化け、SMB は 445 のまま — macOS では
  ホスト自身の smbd に当たり、全資格情報が `52e` で沈む。
- **macOS の UDP :88 影スタブ**は全プリンシパルに `C_PRINCIPAL_UNKNOWN` を返す。
  実物の Samba 4.24 は `PREAUTH_REQUIRED` を返す。判别は `acceptance_battery.sh`
  の check 0 — Kerberos の結果を信じる前に必ず通すこと。
- **Kali 側の nft リダイレクトルールは再起動を跨いで永続化**すること。
  スクリプトはまさにこの理由のため systemd ユニットで導入する。
- Samba KDC の硬化: 4.24 では `DONT_REQ_PREAUTH` を設定しても AS-REP ロースティングは
  ハッシュを返さず、impacket の Kerberoast 要求路は検証和の相互運用壁
  (`KRB_AP_ERR_INAPP_CKSUM`) に当たる。両方とも docs/SOLUTION.md の壁セクションに
  実測付きで記載 — 報告すべきバグではなくラボの一部。

## クレジット

- 基底イメージ: [`stefgo/samba-ad`](https://github.com/stefgo/samba-ad)
  (Stefano Gosso 作) — 最小構成の Samba AD DC コンテナ。本ラボは digest
  (`sha256:d46275b4…`) で固定し ghcr.io から取得するもので、上流のビルド層の
  再配布は行っていません。上流のライセンス: 執筆時点では未宣言 — 公開コンテナ
  イメージとして参照し実名で帰属を示すとともに、LICENSE 追加を求める上流 issue
  ([stefgo/samba-ad#1](https://github.com/stefgo/samba-ad/issues/1)) を起票済み。
- それ以外 (compose・シードロジック・ACL 設計・バッテリー・ドキュメント) は
  本ラボ用に著者が作成し MIT ライセンス (LICENSE 参照)。

## 免責

演習専用。既定資格情報のまま公網に公開しないこと。意図的に脆弱な ID 設計で動いています。
