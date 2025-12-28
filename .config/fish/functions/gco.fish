function gco --description "Fuzzy git checkout branch (sorted by recent)"
  # 1. Get branches sorted by date
  set -l branches (git branch --sort=-committerdate --no-color | grep -v HEAD | string trim | string replace -r "^\\* " "")

  # 2. FZF selection
  #    Changed --preview to show the actual log (last 15 commits) with color
  set -l target (
    printf "%s\n" $branches |
    fzf --no-hscroll --no-multi \
        --ansi \
        --preview="git log -n 15 --color=always --date=short --pretty=format:'%C(auto)%h%d %s %C(green)(%cd) %C(bold blue)<%an>' {}"
  )

  if test -n "$target"
    set -l clean_target (echo "$target" | string replace -r '^remotes/[^/]+/' '')
    git checkout "$clean_target"
  end
end
