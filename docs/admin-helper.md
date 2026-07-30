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

## Policy upgrade

The installed helper policy format is version `2`. Version `1` policies allowed
arbitrary arguments after an executable match and are therefore rejected rather
than migrated broadly. Reinstall the helper with explicit profiles after an
upgrade. A version-2 program entry missing its command list defaults only to the
argument-free compatibility rule.
