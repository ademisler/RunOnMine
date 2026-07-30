# Privileged helper command profiles

The optional helper is absent by default and is never installed by normal setup.
It does not accept shell text. Each request contains one absolute executable path
and an argument vector, and the installed root/SYSTEM-owned policy must approve
both the pinned executable identity and one complete command schema.

## Safe compatibility mode

`--allow-program` creates only an argument-free command profile:

```console
runonmine admin install --allow-program /absolute/root-owned/program
```

That program can be called only with an empty `args` array. Supplying a
subcommand, flag, positional value, or response-file argument is rejected. Use a
profile file for every privileged operation that needs arguments.

## Versioned profile file

A profile is owner-supplied JSON. The current document version is `1`:

```json
{
  "version": 1,
  "programs": [
    {
      "program": "/usr/bin/systemctl",
      "commands": [
        {
          "subcommand": "restart",
          "flags": [
            {
              "name": "--no-block",
              "repeatable": false
            }
          ],
          "forbidden_flags": [
            "--root",
            "--machine",
            "--user"
          ],
          "positionals": [
            {
              "type": "choice",
              "values": [
                "runonmine-agent.service"
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Install it with an absolute path:

```console
runonmine admin install --profile-file /absolute/path/admin-profile.json
```

The unprivileged CLI validates the document before elevation. The elevated
helper validates and normalizes it again before writing the installed policy.
Unknown JSON fields, relative executable paths, empty command lists, duplicate
flags, undeclared flags, missing or extra positionals, response-file syntax, and
control characters fail closed.

## Argument schemas

Each command may define:

- one exact first-position subcommand;
- exact allowed flags, optionally with one typed value and a repeatability rule;
- forbidden flags that override all other matching;
- an exact sequence of positional schemas;
- `choice`, bounded `text`, or constrained `path` values.

A path schema has one or more absolute roots and one mode:

- `existing`;
- `existing_file`;
- `existing_directory`;
- `create_or_existing`.

Roots are canonicalized during installation and revalidated when the installed
policy is loaded. Existing targets are canonicalized, creation targets must have
an approved existing ancestor, and symlink or traversal escapes are rejected.
For example:

```json
{
  "type": "path",
  "roots": [
    "/var/lib/runonmine/staging"
  ],
  "mode": "existing_file"
}
```

Flag values use the same schemas. A flag may be supplied as `--flag value` or
`--flag=value`, but its normalized name, value type, and repeatability must match
the profile exactly.

## Transactional installation and rollback

Installation prepares all three platform artifacts before touching the running
helper:

1. the helper executable is copied to a same-filesystem staging file;
2. the normalized root/SYSTEM policy is serialized to a private staging file;
3. the launchd plist or systemd unit is rendered to a staging file where the
   platform uses a file-backed service definition.

RunOnMine then snapshots the existing executable, policy, service definition,
and whether the service was installed and running. Only after every stage and
snapshot succeeds does it stop the old service and activate the new files. The
new service must start and answer an authenticated helper health request before
the transaction commits.

A binary/policy/service-definition activation error, platform service start
error, or failed health check triggers rollback. The failed service is stopped,
all previous artifacts are restored in reverse order, the former installed and
running state is recreated, and a previously running helper is health-checked
again using the owner from its restored policy. A failed first installation
removes all newly activated files and unregisters the new service instead of
leaving a partial privileged installation.

Staging files live in each destination's parent directory so activation does
not cross filesystems. File modes and Windows ACL hardening are applied again
after activation and restoration, and Unix parent directories are synchronized
after each rename. This transaction handles reported installation failures;
crash-recovery journaling is a separate lifecycle concern.

## Executable identity and spawn races

Executable installation and every execution request use an open file handle,
not a path-only `canonicalize`/hash decision. The final component is opened
without following symlinks where the platform supports that flag. RunOnMine
records the canonical identity and SHA-256 from the opened file, checks that the
handle identity remains stable while hashing, and hashes the same open handle
again immediately before process creation.

Platform behavior differs:

- **Linux:** the verified descriptor has `FD_CLOEXEC` removed only for the
  imminent child and the process is launched through `/proc/self/fd/<fd>`.
  Replacing the original pathname therefore cannot change the inode that is
  executed. The read-only descriptor remains inherited so verified scripts with
  a shebang also continue to resolve their descriptor path.
- **Windows:** the executable is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and
  only `FILE_SHARE_READ`. The retained handle blocks write/delete/replace opens
  while process creation is in progress. Volume serial, file index, size,
  last-write identity, reparse attributes and SHA-256 are checked again before
  `CreateProcess` is reached.
- **macOS and other supported Unix platforms:** RunOnMine retains the verified
  descriptor, compares device/inode identity, reopens the canonical pathname,
  and compares identity plus SHA-256 immediately before spawn. This sharply
  narrows the path replacement window but does not claim the same handle-exec
  guarantee as Linux.

An in-place write to the already opened inode changes its digest and is rejected
before spawn. A privileged actor that can alter kernel behavior or modify the
file after the final platform check remains outside the helper's threat model.

## Policy upgrade

The installed helper policy format is version `2`. Version `1` policies allowed
arbitrary arguments after an executable match and are therefore rejected rather
than migrated broadly. Reinstall the helper with explicit profiles after an
upgrade. A version-2 program entry missing its command list defaults only to the
argument-free compatibility rule.
