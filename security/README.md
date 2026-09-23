# Credential checks

Install the pinned scanner and enable this repository's local commit hook:

```sh
python3 security/install_gitleaks.py
git config --local core.hooksPath .githooks
```

The hook scans the staged versions, including supported archives, so unstaged edits cannot mask staged secrets. CI also scans the entire PR/push commit range to catch a credential added and then deleted before merging. A missing scanner or incomplete scan fails closed. Reports show locations and rule names only.

Use environment variables, Google Application Default Credentials or your deployment platform's secret store. Never commit populated `.env` files, private-key JSON, database dumps or authentication responses. `.env.example` must contain empty values or clear placeholders. Ignoring a file does not remove it from Git history.

For an intentional full scan of the tracked HEAD tree:

```sh
python3 security/scan.py --tree
```

Existing third-party examples/public tokens can make a full-tree scan fail. Review each finding; do not add a broad directory exclusion or suppress a real secret. These checks reduce risk but are not proof that no secret exists. Enable GitHub Secret Scanning and Push Protection where available, and require the credential-check job in the applicable branch ruleset.

After a leak, revoke or rotate the credential at the provider first, update the consuming application, and coordinate history cleanup and all clones/forks. Deleting the current file alone is not remediation. For a suspected compromised server, contain and rebuild it before installing replacement secrets.
