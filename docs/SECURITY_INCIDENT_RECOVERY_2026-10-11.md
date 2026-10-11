# RunOnMine clean-room Git trust reset — 2026-10-11

## Why the public repository needed a new history
Old public ademisler/RunOnMine GitHub repo ID 1304283011 still resolved malicious detached Git blob 50d61c1bbbcd89f4e6d9c9a34f8d3bf2fdacd3ea through GitHub API, even though the visible main tree contained no known editor autorun or fake-font paths. Merely removing branches or writing a clean-looking one-root commit was not sufficient. New canonical repository was created fully empty, without a template, using a separately verified source tree. No old Git object database, refs, hooks, credentials or binaries were imported.

## Trusted current source
- Old active main: 36cde928e233e4bfae64c8752e7a4236e2fabaac.
- Reviewed exact main tree: 50566c9817ab1ca03fdf7dc9b3a4790cdb96dfa3; 262 source files, 3719040 bytes.
- Source path/mode/blob manifest SHA256: c14fdc31b2e78cc408b6922fe717f5e5c8cd37410bcae588d02a8df74e5e1920.
- Fresh parentless Git root: db1fd7b170cea626fa631810495b37331b23858d.
- All tracked source files were individually verified by exact Git blob SHA and byte count and placed in a fresh Git index. The independently recomputed tree exactly matched the review tree, and git fsck --full --strict passed.
- Known malicious blob identities 50d61c1bbbcd89f4e6d9c9a34f8d3bf2fdacd3ea, 27338d3d89c5f0c86cf222cb616f2b2bcbaf1dc1, 326ebce2f768b9c611e07eff50588f86ab81fa2e and bd78eb5e8c17bc9954b5a77cc08bd267d8118b09 fail to resolve in the new repository.

## Static review and isolated tests
- No VS Code folder-open autorun, fake font, known injected script marker, incident downloader, embedded GitHub token or private key found in main source.
- Two long JSON lines are documented signed connector provenance records for cloudflared/openai-tunnel-client and not incident payloads.
- No symlink or gitlink/submodule was present.
- An unauthenticated disposable Modal Linux Sandbox with exact Rust 1.95.0 received only a source tar with no .git. cargo fmt --all -- --check passed; cargo metadata --no-deps --offline --format-version 1 passed. Neither command executes application or dependency build scripts. Full Rust CI and release rebuilding require separately checked hosted jobs.
- No production binaries from prior releases were executed in the clean-room.

## Repository metadata preservation and release caveat
- Old repository must be kept private and archived with all original historical branches, PRs, tags and release attachments preserved as forensic/legitimate metadata.
- New repo is intended to be public under the original exact GitHub URL. Restore the original description, homepage, topics, merge rules, branch protection and restricted GitHub Actions policy.
- Original metadata: 8 branches including main; 7 open PRs; tag v0.1.0-beta.1; one public beta release with 30 assets; 7 topics. No Actions secret, environment secret, repo variable, deploy key, webhook, or Pages hosting was found in captured metadata.
- IMPORTANT: The previous release URLs and PR links refer to the old repository identity and may no longer resolve publicly. Old packaged binaries and archives have NOT been republished because their safety was not independently established. Publish newly verified builds only after trustworthy hosted CI and packaging. Do not take a public beta binary from the old private archive and re-upload it blindly.
- Branch protection formerly required strict status contexts Linux quality, Platform matrix and Dependency review, required linear history and conversation resolution, enforced for admins, prohibited force-push/deletion. GitHub Actions used selected SHA-pinned actions and read-only default token scope. These settings must be restored on new canonical repo, not inherited from untrusted prior Git databases.

## Hosting, backups and secret policy
No Ternrise production release or workstation checkout is implicitly safe to sync. Each active trust path must be inventoried, preservation-reviewed and clean-history-synced independently before use. Do not rebuild/redeploy healthy production solely for the Git metadata reset.
Root-only audit /root/forensics/runonmine-final-github-20261011 retains preflight metadata, old release asset names and hashes when exposed, source scan, exact root/archive hashes and host checks. Never restore old Git credentials, untrusted Git objects, pre-incident secret values or old release binaries.
