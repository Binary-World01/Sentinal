import sys
import os
from dulwich import porcelain
from dulwich.repo import Repo

repo_path = os.path.dirname(os.path.abspath(__file__))
remote_base = "github.com/Binary-World01/Sentinal.git"

token = os.environ.get("GITHUB_TOKEN", "")
if len(sys.argv) > 1:
    token = sys.argv[1].strip()

if not token:
    print("Usage: python push.py <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>")
    sys.exit(1)

auth_remote = f"https://harry1365:{token}@{remote_base}"

print(f"Staging all files in {repo_path}...")
porcelain.add(repo_path, paths=["."])

try:
    porcelain.commit(
        repo_path,
        message="AP Payment Fraud Sentinel - RocketRide Multi-Agent Forensic AI with Supabase Auth & Vendor Registry",
        author="harry1365 <harry1365@users.noreply.github.com>",
        committer="harry1365 <harry1365@users.noreply.github.com>"
    )
except Exception as e:
    pass

try:
    porcelain.push(
        repo_path,
        remote_location=auth_remote,
        refspecs=["refs/heads/main:refs/heads/main"],
        force=True
    )
    print("SUCCESS: Pushed to GitHub successfully!")
except Exception as e:
    print(f"PUSH_ERROR: {e}")
