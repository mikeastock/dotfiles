function wtc --description "Fuzzy jump to a git worktree by branch"
  if not git rev-parse --show-toplevel >/dev/null 2>&1
    echo "wtc: not inside a git repository" >&2
    return 1
  end

  set -l entries
  set -l worktree ""
  set -l branch ""

  for line in (git worktree list --porcelain)
    if test -z "$line"
      if test -n "$worktree"; and test -n "$branch"
        set -l branch_name (string replace 'refs/heads/' '' -- "$branch")
        set -a entries "$worktree	$branch_name"
      end
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

  if test -n "$worktree"; and test -n "$branch"
    set -l branch_name (string replace 'refs/heads/' '' -- "$branch")
    set -a entries "$worktree	$branch_name"
  end

  if test (count $entries) -eq 0
    echo "wtc: no worktrees with branches found" >&2
    return 1
  end

  set -l selected (
    printf "%s\n" $entries |
    fzf --no-hscroll --no-multi \
        --ansi \
        --with-nth=2 \
        --delimiter='\t' \
        --preview="git -C {1} log -n 15 --color=always --date=short --pretty=format:'%C(auto)%h%d %s %C(green)(%cd) %C(bold blue)<%an>'"
  )

  if test -n "$selected"
    set -l dest (string split -f 1 \t -- "$selected")
    cd "$dest"
  end
end
