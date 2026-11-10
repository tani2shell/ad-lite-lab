# ad-lite-lab — 单容器 Active Directory 靶场

[English](README.md) | [日本語](README.ja.md) | **简体中文**

一个紧凑的 Active Directory 攻击靶场：一台 Samba 4.24 域控
（`dc01.lite.corp`，域 `LITE.CORP`）装进单个 Docker 容器，预置用户、组、
服务账号、委派和一条精心设计的 ACL 链。2 个 flag，1 条预期路径，无需
Windows 授权，约 1.5 GB 内存。

专为练习多 VM 靶场里最烧钱的 AD 实战技能：匿名面枚举、字典可达的入口凭据、
ACL 侦查、组成员关系滥用、读取普通绑定看不到的数据。预期解见
[docs/SOLUTION.md](docs/SOLUTION.md)——解完（或认输）之前别打开。

## 为什么做这个

GOAD 级全家桶要 3 台以上 Windows VM、12–18 GB 内存，在 Apple Silicon 上
基本跑不动。`ad-lite-lab` 把*身份攻击面*（枚举 → 进门 → ACL 滥用 →
复制范围数据）收进一个 ARM64 友好的容器，同时保证每一步在盲态下都真实可解。
本靶由 AI agent 攻击流水线构建并标定（见下方[实战标定](#实战标定)）——
你能撞到的墙，机器先替你撞过；每个线索都验证过可达。

## 前置要求

- Docker（Engine / OrbStack / Docker Desktop）或支持 compose 的 Podman
- DC 容器需要 2 vCPU / 2 GB 空闲内存
- 一台能访问容器发布端口的攻击机（推荐 Kali；`scripts/` 假设 Debian 系 + sudo）
- 攻击机与 DC 时钟偏差 5 分钟以内（Kerberos 常识）

## 快速开始

```bash
git clone https://github.com/tani2shell/ad-lite-lab.git
cd ad-lite-lab

# 1. 一键起靶：生成 secrets.env 和 flag → 建域 → 起 DC → 等 LDAP 端口 →
#    播种账号/组/ACL/flag
./forge_samba.sh provision        # 首次约需几分钟

# 2. 确认 DC 活着
./forge_samba.sh status
./forge_samba.sh logs 50

# 3.（攻击机侧）域名解析 + Kerberos realm 接线
sudo bash scripts/kali_wiring.sh  # 写 /etc/hosts 和 /etc/krb5.conf.d
```

DC 除 AD 标准端口外，还镜像发布 `1088`（Kerberos）和 `1445`（SMB）——
macOS 上宿主系统会抢先把 88/445 占掉，见[平台矩阵](#平台矩阵)。默认攻击姿态：

| 项目 | 值 |
|---|---|
| 域 | `LITE.CORP`（NetBIOS：`LITE`） |
| DC 主机名 | `dc01.lite.corp` |
| `-dc-ip` | 攻击机能到达的 Docker 宿主地址（见平台矩阵） |
| SMB 端口 | Linux 用 `445`；macOS 用 `--port 1445`（netexec 用 `--port`，**不是** `-p`） |

运维命令：

```bash
./scripts/acceptance_battery.sh   # 7 项健康电池（在攻击机上跑）
bash scripts/reseed.sh            # 幂等重播种（flag 值不变）
./forge_samba.sh reset            # 全清 → 重建 → 重播种
./forge_samba.sh down             # 停止（卷保留）
```

### 自定义 flag 与凭据

首次 provision 生成 `secrets.env`（不入库），内含域管理员/服务凭据和两个
flag 值，格式见 `secrets.env.example`。改完后跑 `scripts/reseed.sh` 重新生效。
flag 值同时落在 `flags/local.flag` / `flags/proof.flag` 供计分侧使用；
解题者从 AD 里读，不从磁盘读。

## 箱内有什么（无剧透）

- 1 台域控，2 个公开 flag，1 条预期链，若干诱饵
- SPN、委派标志、分层组、自定义 schema 属性等真实 AD 怪癖
- 域策略调校到字典喷射可进门且可复现
- `docs/SOLUTION.md`——预期路径、备用路线，以及"设计出来的墙"与
  "Samba 与 Windows 实现差异的墙"的区分

## 实战标定

以下数字均为作者方 AI agent 攻击流水线在本参考环境的实测——
**Apple M5 Ultra、本地 oMLX Qwen3.8-Flash-Next 模型、OrbStack Kali（ARM64）攻击机**。
换模型/硬件会更快或更慢；请当作一个标定点，而非保证。

- 预期解时长带（知情 agent）：**20–40 分钟**
- 盲态字典喷射约 **2 万–12 万请求**可打到入口凭据（实测；入口口令是主流
  top-50k 字典的逐字节精确成员）
- 枚举完备性：250 万请求盲跑经三轮独立枚举，无遗漏地覆盖全部有效主体集

## 平台矩阵

| 宿主 | 攻击姿态 | 说明 |
|---|---|---|
| Linux（原生 Docker） | 直连标准端口 88/445/389… | 指向宿主 IP；宿主自身 smbd 不占 445 即可用 |
| macOS（OrbStack / Docker Desktop） | 镜像端口：Kerberos `1088` / SMB `1445` | macOS 文件共享会在 Docker 之前静默抢占 :88/:445。`scripts/kali_kdc_relay.sh` + `scripts/kali_nft_persist.sh` 安装 systemd 持久的 `:88 → :1888 → host:1088` 重定向，AD 工具可保持默认姿态；SMB 工具必须 `--port 1445`。任何 Kerberos 结论生效前先过 `acceptance_battery.sh` check 0 |
| WSL2（WSL2 内 Docker） | 能发布到 WSL2 网络就按 Linux 处理 | Windows 宿主也常占 445——拿不准就走 1445 镜像 + Kali 脚本 |
| Windows（Docker Desktop） | 同 macOS 走镜像端口 | 宿主 smbd 通常占 445；停掉或用 1445 |
| CPU 架构 | arm64 / amd64 均支持 | 基础镜像多架构；本靶在 arm64 上构建并标定 |

## 已知环境怪癖（都是交过学费的，不必二次付费）

- **netexec 的 `-p` 是密码不是端口。** 端口用 `--port 1445`。传 `-p 1445`
  会把"密码"当端口发出去、SMB 停在 445——在 macOS 上静默命中宿主自己的
  smbd，全部凭据报 `52e`。
- **macOS 的 UDP :88 影子桩**对任何主体都回 `C_PRINCIPAL_UNKNOWN`，真身
  Samba 4.24 回 `PREAUTH_REQUIRED`。判别器是 `acceptance_battery.sh` 的
  check 0——信任何 Kerberos 结果之前先过它。
- **Kali 侧 nft 重定向规则必须跨重启持久**——脚本正是为此装成 systemd 单元。
- Samba KDC 硬化：4.24 上即使设了 `DONT_REQ_PREAUTH`，AS-REP 挑刺也不出
  hash；impacket 的 Kerberoast 请求路撞校验和互操作墙
  (`KRB_AP_ERR_INAPP_CKSUM`)。两者在 docs/SOLUTION.md 墙清单里都有实测记录
  ——它们是靶的一部分，不是该提的 bug。

## 致谢

- 基础镜像：[`stefgo/samba-ad`](https://github.com/stefgo/samba-ad)，作者
  Stefano Gosso——极简 Samba AD DC 容器。本靶按 digest 钉版
  （`sha256:d46275b4…`）从 ghcr.io 拉取，不再分发上游构建层。基础镜像许可：
  撰写时上游未声明 LICENSE——我们按公共容器镜像引用并实名署名，并将向上游
  提 issue 请求补 LICENSE。
- 本仓库其余内容（compose、播种逻辑、ACL 设计、电池脚本、文档）为本靶原创，
  MIT 授权（见 LICENSE）。

## 免责

仅供练习。默认凭据状态下切勿把 DC 暴露到公网；它跑的是刻意脆弱的身份设计。
