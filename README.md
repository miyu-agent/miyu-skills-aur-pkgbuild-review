# AUR 包审查

Miyu 包：一个技能 `aur-pkgbuild-review` 加一件工具 `aur_review`。装 AUR 包之前让 AI 查一遍 PKGBUILD、安装脚本和最近的提交。

审查办法和定级规则照 [shorin-pac](https://github.com/SHORiN-KiWATA/shorin-pac) 的 `pac`（`prompts/aur-review.md` 和 `bin/pac` 的证据收集、定级）：**AI 只报带原文证据的信号，级别由脚本照固定规则算**；AI 引用的那一行在原文里找不到的，恶意降为可疑，其余不算数。

## 工具 `aur_review`

| 参数 | 说明 |
|---|---|
| `action` | `collect`（默认）：收证据；`score`：给 AI 报的信号定级 |
| `package` | AUR 包名 |
| `findings` | 只给 `score`：信号数组，每条 `category`、`file`、`evidence`（逐字一行）、`summary`；没发现给 `[]` |
| `intent`、`notes` | 只给 `score`：包装的是什么、给用户的一两句提醒 |
| `format` | `md`（默认）或 `json` |

`collect` 收的东西：AUR RPC 元数据；克隆 `https://aur.archlinux.org/<pkgbase>.git`（没有 git 时退到 cgit 快照，历史标不可用）；git 历史（至多 128 条）；最近 3 次提交的完整 diff（至多 48 KiB）；信任背景（新包、新提交者算弱，满一年且 50 票算强）；PKGBUILD 的 source 里写着、`.SRCINFO` 里却没有的主机；每个文件的全文（二进制、非 UTF-8、链接只给元数据）。文件超过 128 个、单个超过 128 KiB 或合计超过 512 KiB 的不审，直接报错。证据存在 `MIYU_SCRIPT_CACHE_DIR`，`score` 拿它核实引用。

定级：任一条核实过的恶意 → 高；两类以上可疑 → 高；一类可疑且信任弱 → 高；一类可疑 → 中；只有卫生项且信任弱 → 中；构建时拉未锁定的依赖且信任不强 → 中；其余 → 低。

## 注意

- 只读：不构建、不安装、不运行包里的任何东西。装不装由用户决定，审查完 AI 给出 `paru -S`/`yay -S` 让用户自己跑。
- 需要能联网到 `aur.archlinux.org`；`git` 可选。
- 只用 Python 标准库。
