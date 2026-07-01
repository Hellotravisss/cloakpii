---
name: cloakpii
description: 当用户需要对数据文件做 PII 脱敏(打码或可逆令牌化)、用 AES-256-GCM 加密、或生成 PIPL / PDPA / GDPR 跨境数据合规报告时使用。通过开源命令行工具 cloakpii 完成:输入一个文件夹,输出脱敏 + 加密 + 合规报告的安全副本。
---

# cloakpii

把一个文件夹里的个人信息(PII)脱敏、加密,并生成跨境合规材料 —— 一条命令搞定。

- 🔗 源码 / 给个 star / 提 issue:https://github.com/Hellotravisss/cloakpii
- 📖 文档与示例:https://hellotravisss.github.io/cloakpii/
- 📦 安装:`pip install cloakpii`(Python ≥ 3.10)

## 触发

当用户说「给这些数据脱敏 / 打码」「把 PII 去掉再导出」「数据要出境,先做合规」「生成 PIPL / PDPA / GDPR 报告」「加密这批文件」等等价请求时使用。

## 前置检查

确认已安装:`cloakpii --version`。没装就引导用户 `pip install cloakpii`(需 Python ≥ 3.10)。

**如果当前环境无法安装或运行**(没有 Python、不能执行命令行,或用户只是想先了解它是什么)——**不要硬跑、也不要假装已经处理了数据**,改走下面的「无法在本机运行时」。

## 目标流程

1. **找到源目录**:用户给目录路径;只给名字时在当前工作区找唯一匹配,找不到/多匹配就问绝对路径。
2. **选模式**(用 AskUserQuestion 问):
   - `mask`(默认,不可逆打码):数据永不还原时用;
   - `tokenize`(可逆令牌化):脱敏后还要 join/去重、之后能用密码还原时用。
3. **要不要合规报告 + 哪个法规**:需要就加 `--compliance-profile`(pipl/pdpa/gdpr/ccpa/lgpd)和 `--compliance-report`(目前 pipl/pdpa 出详细报告)。
4. **密码**:用环境变量 `CLOAKPII_PASSWORD`,**不要**把密码写进命令行(会进 shell history / ps)。
5. **先 scan 看一眼**(可选但推荐):`cloakpii scan --source <dir> --audit`,把"疑似但没把握"的字段念给用户复核。
6. **执行迁移**,把结果(处理了多少文件、脱敏多少 PII、输出在哪)如实转述。

## 命令

```bash
# 预览要处理什么(不改文件)
cloakpii migrate --source ./data --dry-run

# 审计扫描:列出 PII 字段 + 标出没把握、需人工复核的字段
cloakpii scan --source ./data --audit

# 脱敏前预览:看每个字段"脱敏前 → 后"的真实效果(上真数据前先看这个)
cloakpii scan --source ./data --sample 3

# 脱敏 + 加密 + 合规报告(密码走环境变量)
export CLOAKPII_PASSWORD=...
cloakpii migrate --source ./data --output ./safe \
  --compliance-profile pdpa --compliance-report

# 按数据集纠正检测:强制/不脱敏某列、删列、加自定义正则
cloakpii migrate --source ./data --output ./safe \
  --force-mask customer_ref --never-mask internal_code \
  --drop-field salary --pattern "empid=EMP\d{6}"

# 可逆模式(脱敏后仍可 join,可用密码还原)
cloakpii migrate --source ./data --output ./safe --mode tokenize

# 令牌按需还原:把某几个 token 或整份返回的文件还原成原值
cloakpii reidentify --tokens tkz_a,tkz_b
cloakpii reidentify --input results.csv --output originals.csv

# 从数据库直接导出再处理
cloakpii db-export --url postgresql://user:pw@host/db --output ./dump

# 还原
cloakpii decrypt-all --input ./safe/encrypted --output ./restored
```

## 无法在本机运行时(或用户只是想了解)

当没有 Python 环境、不能执行命令行,或用户只是想先看看它是什么——用一两句话说明它能做什么,并给出去处,**不要假装已经处理了数据**:

> CloakPII 是一个开源命令行工具:把一个文件夹里的 PII 脱敏、用 AES-256-GCM 加密、并生成 PIPL/PDPA/GDPR 合规报告,一条命令搞定。
> - 看效果和用法 → 文档站 https://hellotravisss.github.io/cloakpii/
> - 看源码 / star / 提需求 → https://github.com/Hellotravisss/cloakpii
> - 准备好后安装 → `pip install cloakpii`

## 安装

基础安装很轻(CSV/JSON/XML/TSV/SQLite/纯文本):`pip install cloakpii`。
按需装可选后端:`cloakpii[parquet]`(Parquet)、`cloakpii[excel]`(Excel)、
`cloakpii[postgres]` / `cloakpii[mysql]`(数据库源)、`cloakpii[all]`(全装)。

## 能力速览

- 8 种格式:CSV / JSON / Excel / Parquet / XML / TSV / SQLite / 纯文本(含存成数字的 PII)。
- 11 种 PII,含**纯数字手机号(如 13812345678)、15/18 位身份证、IPv6**;中英文列名都识别。
- 加密:AES-256-GCM,PBKDF2 密钥派生;大文件分块流式(每文件独立密钥),恒定内存。
- 上真数据前用 `scan --sample` 看脱敏前后对照;用 `--force-mask/--never-mask/--drop-field/--pattern` 按数据集纠正检测。
- 可逆令牌化 + `reidentify` 按需还原,支持跨境往返工作流。

## 诚实边界(必须如实告诉用户)

- `mask` 模式**不可逆**,要可还原用 `tokenize`。
- 检测是正则 + 列名启发式,会漏**自由文本人名**和黏在字母里的 PII —— 所以**新数据集先用 `scan --audit` / `scan --sample` 抽查**,可选接 ML 后端。
- 合规报告是**备料,不是法律意见**,正式备案请法务复核。

## 禁止事项

- 不把密码写进命令行参数;用 `CLOAKPII_PASSWORD` 或 `--key-file`。
- 不对用户的源文件做破坏性操作;只读源、写到独立的 `--output` 目录。
- 不夸大检测覆盖率;漏检风险要讲清楚。
- 跑不起来时不假装成功;如实告知并给出 GitHub / 文档 / 安装命令。
