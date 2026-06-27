function cleanup_merged_worktrees -d "List merged git worktrees; pass --cleanup to remove merged worktrees"
  argparse 'c/cleanup' 'f/force' 't/target=' 'h/help' -- $argv
  or return 2

  if set -q _flag_help
    echo "usage: cleanup_merged_worktrees [--cleanup] [--force] [--target origin/main]"
    echo ""
    echo "Default is dry-run. With --cleanup, removes clean worktrees merged into target and deletes their branches. Add --force to discard dirty merged worktrees."
    return 0
  end

  set -l target origin/main
  if set -q _flag_target
    set target $_flag_target
  end

  if not git rev-parse --show-toplevel >/dev/null 2>&1
    echo "cleanup_merged_worktrees: not inside a git repository" >&2
    return 1
  end

  git fetch origin
  or return $status

  set -l porcelain (git worktree list --porcelain)
  set -l worktree ""
  set -l branch ""

  function __cleanup_merged_worktrees_process --argument-names worktree branch target cleanup force
    if test -z "$worktree"; or test -z "$branch"
      return 0
    end

    set -l branch_name (string replace 'refs/heads/' '' -- "$branch")

    if test "$branch_name" = "main"
      return 0
    end

    if not git merge-base --is-ancestor "$branch_name" "$target" 2>/dev/null
      echo "NOT MERGED $branch_name"
      echo "           $worktree"
      return 0
    end

    echo "MERGED     $branch_name"
    echo "           $worktree"
    set -g __cleanup_merged_worktrees_merged_count (math $__cleanup_merged_worktrees_merged_count + 1)

    if test "$cleanup" != "1"
      return 0
    end

    set -l remove_args
    set -l branch_delete_arg -d

    if test -n "$(git -C "$worktree" status --short)"
      if test "$force" != "1"
        echo "           skipped: dirty worktree"
        set -g __cleanup_merged_worktrees_skipped_dirty_count (math $__cleanup_merged_worktrees_skipped_dirty_count + 1)
        return 0
      end

      echo "           force removing dirty worktree"
      set remove_args --force
      set branch_delete_arg -D
    end

    git worktree remove $remove_args "$worktree"
    and git branch $branch_delete_arg "$branch_name"
    and set -g __cleanup_merged_worktrees_removed_count (math $__cleanup_merged_worktrees_removed_count + 1)
  end

  set -g __cleanup_merged_worktrees_merged_count 0
  set -g __cleanup_merged_worktrees_removed_count 0
  set -g __cleanup_merged_worktrees_skipped_dirty_count 0

  set -l cleanup 0
  set -l force 0
  if set -q _flag_cleanup
    set cleanup 1
  end
  if set -q _flag_force
    set force 1
  end

  for line in $porcelain
    if test -z "$line"
      __cleanup_merged_worktrees_process "$worktree" "$branch" "$target" "$cleanup" "$force"
      set worktree ""
      set branch ""
      continue
    end

    if string match -q 'worktree *' -- "$line"
      set worktree (string replace 'worktree ' '' -- "$line")
    else if string match -q 'branch *' -- "$line"
      set branch (string replace 'branch ' '' -- "$line")
    end
  end

  __cleanup_merged_worktrees_process "$worktree" "$branch" "$target" "$cleanup" "$force"
  functions -e __cleanup_merged_worktrees_process

  if set -q _flag_cleanup
    echo "Removed $__cleanup_merged_worktrees_removed_count merged worktree(s); skipped $__cleanup_merged_worktrees_skipped_dirty_count dirty merged worktree(s)."
  else
    echo "Dry run: found $__cleanup_merged_worktrees_merged_count merged worktree branch(es). Pass --cleanup to remove clean ones or --cleanup --force to remove dirty ones too."
  end

  set -e __cleanup_merged_worktrees_merged_count
  set -e __cleanup_merged_worktrees_removed_count
  set -e __cleanup_merged_worktrees_skipped_dirty_count
end
