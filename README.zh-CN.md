<p align="center">
  <a href="README.md">English</a> | 简体中文
</p>

# AUR 软件包审查

> <sub>本文档由 Anthropic 的 Claude Fable 5.2 生成。</sub>

这是 Miyu 的一个技能软件包，提供一个技能 `aur-pkgbuild-review` 和一件工具 `aur_review`。它的用途是在安装 AUR 软件包之前，让 AI 检查一遍 PKGBUILD、安装脚本和最近的提交。

审查的方法和定级的规则沿用 [shorin-pac](https://github.com/SHORiN-KiWATA/shorin-pac) 的 `pac`（`prompts/aur-review.md`，以及 `bin/pac` 里的证据收集和定级）：**AI 只报告带有原文证据的信号，级别由脚本按固定的规则计算**；如果 AI 引用的那一行在原文里找不到，恶意的信号降为可疑，其他信号不算数。

## 工具 `aur_review`

工具的参数如下：

| 参数 | 说明 |
|---|---|
| `action` | 要执行的操作：`collect`（默认）收集证据；`score` 给 AI 报告的信号定级。 |
| `package` | AUR 软件包的名字。 |
| `findings` | 只用于 `score`：信号的数组，每一条包含 `category`、`file`、`evidence`（逐字摘录的一行原文）和 `summary`；没有发现时传 `[]`。 |
| `intent`、`notes` | 只用于 `score`：这个软件包安装的是什么，以及给用户的一两句提醒。 |
| `format` | 输出的格式：`md`（默认）或 `json`。 |

`collect` 收集的内容包括：AUR RPC 的元数据；克隆下来的 `https://aur.archlinux.org/<pkgbase>.git`（没有 `git` 时改用 cgit 的快照，此时历史标为不可用）；`git` 历史（最多 128 条）；最近 3 次提交的完整差异（diff，最多 48 KiB）；信任背景（新的软件包、新的提交者算弱，满一年并且有 50 票算强）；PKGBUILD 的 `source` 里写了、`.SRCINFO` 里却没有的主机；每个文件的全文（二进制文件、非 UTF-8 的文件和链接只给元数据）。如果文件超过 128 个、单个文件超过 128 KiB 或者合计超过 512 KiB，工具不做审查，直接报错。证据存在 `MIYU_CACHE_DIR`，`score` 用这些证据核实引用。

定级的规则如下：任何一条核实过的恶意信号 → 高；两类以上的可疑信号 → 高；一类可疑信号并且信任弱 → 高；一类可疑信号 → 中；只有卫生项并且信任弱 → 中；构建时拉取未锁定的依赖并且信任不强 → 中；其他情况 → 低。

## 注意

使用这个技能时，要注意以下几点：

- 审查是只读的：工具不构建、不安装，也不运行软件包里的任何东西。是否安装由用户决定；审查完成后，AI 会给出 `paru -S`/`yay -S` 命令，让用户自己运行。
- 工具需要能联网访问 `aur.archlinux.org`；`git` 是可选的。
- 这个工具只使用 Python 标准库。
