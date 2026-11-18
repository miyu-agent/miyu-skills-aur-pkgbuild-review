# aur_review.py 读新环境变量名的测试（审计 2026-11-18 #168）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库，不联网：只跑 score，证据档预先放进缓存目录。HOME、XDG_*、MIYU_* 都指到临时目录。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "aur_review.py"


class EnvNames(unittest.TestCase):
    # 审计 #168：核心 FH-6 以后只给新名字 MIYU_CACHE_DIR，旧名 MIYU_SCRIPT_CACHE_DIR 会删。
    # main() 只读旧名：只设新名时 score 找不到 collect 存下的证据档，报「还没收过」。
    def test_score_reads_dossier_from_new_env_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cache = root / "cache"
            (cache / "dossiers").mkdir(parents=True)
            (cache / "dossiers" / "demo.json").write_text(json.dumps({
                "package": "demo", "collected_at": 1,
                "aur_rpc": {"Name": "demo", "URL": "https://github.com/example/demo"},
                "aur_git_history": "", "recent_changes": "",
                "trust_context": {"package_age_days": 400, "votes": 100, "orphan": False,
                                  "newest_commit_author_is_new": False,
                                  "newest_author_first_seen_days_ago": 400, "trust": "strong"},
                "checks": {"srcinfo_extra_hosts": []},
                "files": [{"path": "PKGBUILD", "content": 'url="https://github.com/example/demo"\n'}],
            }), encoding="utf-8")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
                   "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root),
                   "XDG_STATE_HOME": str(root), "XDG_DATA_HOME": str(root),
                   "MIYU_CACHE_DIR": str(cache)}
            p = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT)],
                               input=json.dumps({"action": "score", "package": "demo",
                                                 "format": "json", "findings": []}),
                               capture_output=True, text=True, timeout=10, env=env)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            result = json.loads(p.stdout)
            self.assertEqual(result["package"], "demo")
            self.assertEqual(result["level"], "low")


if __name__ == "__main__":
    unittest.main()
