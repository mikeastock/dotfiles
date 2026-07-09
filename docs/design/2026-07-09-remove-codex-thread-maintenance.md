# Remove Codex Thread Maintenance

## Goal

Remove the automated Codex thread archiving and project-prefixing workflows from both this machine and the dotfiles repository. Preserve existing `/tmp` logs and reports.

## Design

Capture the user's live crontab to a file, then classify each block bounded by these exact markers:

- `# BEGIN codex-archive-old-threads` through `# END codex-archive-old-threads`
- `# BEGIN codex-prefix-thread-projects` through `# END codex-prefix-thread-projects`

For each job, exactly one complete block may be present or both markers may be absent. If both complete blocks are present, remove them. If both are absent, continue because the cron removal is already complete. Abort without changing the crontab if any marker is partial, duplicated, or nested, or if only one of the two job blocks is present.

Create the expected crontab by removing only the two exact bounded byte ranges from the captured file, including the blank line within each block. Install that file, reread the crontab to a second file, and use `cmp` against the expected file; this preserves and checks trailing-newline behavior as well as unrelated content. A failed update stops the entire removal.

Before deleting repository scripts, inspect their exact installed paths at `~/.local/bin/codex-archive-old-threads` and `~/.local/bin/codex-prefix-thread-projects`. Each path must be absent or a symlink resolving to its corresponding repository script; stop on a regular file or unexpected symlink target. Remove the verified symlinks before their source files. The repository's generic cleanup target discovers links by enumerating current `bin/*`, so it cannot remove these links after the source files are deleted.

Delete the repository files that exist only for these workflows:

- both cron configuration files
- both thread-maintenance executables
- the shared Codex RPC client
- the mock RPC server
- the prefixer test

Do not keep compatibility wrappers, disabled cron entries, or dormant RPC code. Repository-wide searches, excluding this historical design record, must show no remaining references to the removed commands or helper.

## Failure Handling

If a managed block is malformed or lacks either boundary marker, stop without changing the crontab. If installing or verifying the edited crontab fails, stop before unlinking or deleting any code.

## Verification

- Confirm neither managed block nor command remains in `crontab -l`.
- Confirm the installed command paths satisfy both `! -e` and `! -L`.
- Confirm the deleted repository paths are absent.
- Search the repository, excluding this design record, for command and helper references.
- Run `./tests/test-make.sh` and `./tests/test-install-configs.sh`.
- As a one-time deletion verification, run `make dot-home-symlinks` with `HOME` set to a temporary sandbox. Confirm an unrelated command such as `pi-install` is installed as a symlink, and confirm neither removed command exists as a path or symlink. No permanent regression test is needed because the removed files cannot re-enter the generic `bin/*` installer without being added to the repository again.
- Leave `/tmp/codex-archive-old-threads*` and `/tmp/codex-prefix-thread-projects*` untouched.
