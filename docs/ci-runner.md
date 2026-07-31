# Self-hosted CI runner

RunOnMine's consolidated Linux quality job and the self-hosted Linux portions
of scheduled security, coverage, fuzz, mutation, and soak workflows use a
dedicated unprivileged
`runonmine-ci` account. Hosted macOS, Windows, Linux ARM, and artifact-preflight
jobs do not use this account. The account must not inherit HOME, Cargo
directories, or PATH entries from an administrator or another user.

The runner service must define:

```ini
[Service]
Environment="HOME=/home/runonmine-ci"
Environment="USER=runonmine-ci"
Environment="LOGNAME=runonmine-ci"
Environment="CARGO_HOME=/home/runonmine-ci/.cargo"
Environment="RUSTUP_HOME=/home/runonmine-ci/.rustup"
Environment="PATH=/home/runonmine-ci/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

The runner's captured `.env` and `.path` files must be owned by
`runonmine-ci:runonmine-ci`, use mode `0600`, and contain no path under another
user's home directory. Restart the runner after changing either file.

Every self-hosted workflow sets the same environment defensively and runs
`scripts/ci/verify-runner-environment.sh`. The verifier fails closed on a wrong
account, wrong HOME/Cargo directories, relative or empty PATH entries,
cross-user home paths, symlinked captured environment files, or permissive file
modes.

Build outputs use a job-specific directory below `RUNNER_TEMP` and are removed
with an `always()` cleanup step. A completed job must not leave a workspace
`target/` directory or a `runonmine-*` target directory under runner temp.


## Hosted runner distinction

A self-hosted job proves only the checks it executes on the isolated Linux
runner. It does not substitute for hosted macOS, Windows, ARM, or clean-image
artifact jobs. Conversely, a hosted job that has no runner name and no executed
steps did not test RunOnMine; record it as a runner-allocation blocker and retain
the platform gate as pending or blocked.
