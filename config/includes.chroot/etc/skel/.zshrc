# PH4NTXM Terminal

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

autoload -Uz colors && colors
setopt prompt_subst

C_CYAN='%F{#00abff}'
C_MAGENTA='%F{#ff3dfb}'
C_ERR='%F{#ff0000}'
C_TXT='%F{#d0d0d0}'
C_RESET='%f'

context() {
  print -r -- "${C_CYAN}[${C_MAGENTA}PH4NTXM${C_CYAN}]${C_RESET}"
}

git_branch() {
  local b
  b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || return
  if ! git diff --quiet --ignore-submodules -- 2>/dev/null \
     || ! git diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
    print -r -- " ${C_ERR}($b ✘)${C_RESET}"
  else
    print -r -- " ${C_MAGENTA}($b)${C_RESET}"
  fi
}

exit_status() {
  local s=$?
  [[ $s -ne 0 ]] && print -r -- "${C_ERR}✘$s${C_RESET} "
}

current_dir() {
  print -P "%~"
}

PROMPT='${C_CYAN}┌─ $(context) | $(current_dir)$(git_branch)
${C_CYAN}└─⮞ ${C_RESET}'
RPROMPT='$(exit_status)${C_TXT}%*${C_RESET}'

setopt auto_cd
setopt interactivecomments
unsetopt correct

export HISTFILE=~/.zsh_history
export HISTSIZE=100
export SAVEHIST=100
setopt share_history
setopt hist_ignore_all_dups
setopt hist_ignore_space

print -P "%F{#00abff}[+] PH4NTXM Terminal initialized.%f"