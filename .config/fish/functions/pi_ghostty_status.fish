function pi_ghostty_status --description "Emit Ghostty OSC status/progress/notification sequences"
    if test "$TERM_PROGRAM" != "ghostty"
        return 0
    end

    set -l action "$argv[1]"
    set -l title "$argv[2]"
    set -l body "$argv[3]"

    function __pi_ghostty_sanitize --argument value
        set -l out "$value"
        set out (string replace -a ';' ' ' -- "$out")
        set out (string replace -a '\a' ' ' -- "$out")
        set out (string replace -a '\e' ' ' -- "$out")
        string trim -- "$out"
    end

    switch "$action"
        case running
            printf '\e]9;4;3\a'
        case waiting
            printf '\e]9;4;4\a'
        case stalled
            printf '\e]9;4;4\a'
        case done
            printf '\e]9;4;1;100\a'
        case failed
            printf '\e]9;4;2;100\a'
        case clear new
            printf '\e]9;4;0\a'
        case notify
            set -l safe_title (__pi_ghostty_sanitize "$title")
            set -l safe_body (__pi_ghostty_sanitize "$body")
            printf '\e]777;notify;%s;%s\a' "$safe_title" "$safe_body"
    end
end
