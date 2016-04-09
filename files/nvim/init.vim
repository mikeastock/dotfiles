"
" Michael Stock's vimrc
"
" github.com/mikeastock/dotfiles
"

"Colorscheme settings
let g:gruvbox_italic=0
let g:gruvbox_contrast_dark='hard'

"##############################################################################
"# VIM PLUG SETUP
"##############################################################################
if filereadable(expand("~/.config/nvim/plugins.vim"))
  source ~/.config/nvim/plugins.vim
endif

"##############################################################################
"# BASIC EDITING CONFIGURATION
"##############################################################################

syntax on
filetype plugin indent on
set nocompatible
set relativenumber
set wildmenu
set backspace=indent,eol,start

set tabstop=2
set shiftwidth=2
set expandtab
set smarttab
set autoindent

set splitbelow
set splitright

set history=500
set autoread
set laststatus=2
set tags=./tags;
set hlsearch
set ignorecase smartcase
set hidden

set shiftround " When at 3 spaces and I hit >>, go to 4, not 5.
set gdefault " assume the /g flag on :s substitutions to replace all matches in a line
" I HATE MICE
set mouse=""

"Color and UI
let g:seoul256_background = 233
colorscheme seoul256
" set background=dark

set colorcolumn=80
set cursorline
set ruler
set synmaxcol=250

"SPEEEEEEEEEEEEEED
set re=1
set updatetime=750

let mapleader = " "

"##############################################################################
"# KEY BINDINGS
"##############################################################################

"LEADER
map <Leader>ag :topleft 20 :split Gemfile<CR>
map <Leader>ar :topleft :split config/routes.rb<CR>
map <Leader>bi :terminal bundle install<cr>
map <Leader>tp :terminal bundle exec rake db:test:prepare<cr>
map <Leader>c ::bp\|bd #<CR>
" map <Leader>e :RuboCop<CR>
map <Leader>f :Files<CR>
map <Leader>i mmgg=G`m<CR>
map <Leader>kw :%s/\s\+$//<CR>
map <Leader>q :bd<CR>
" map <Leader>t :terminal<CR>
map <Leader>rs :s/'/"<CR>
map <Leader>vi :e ~/.config/nvim/init.vim<CR>
map <Leader>w :w!<CR>
map <Leader>hs :s/:\([^ ]*\)\(\s*\)=>/\1:/g<CR>
map <Leader>mi 0f:wywOit "pA" doj==oendkf{edi}Op==j0ftlvt.c(response)<CR>
map <Leader>gs :Gstatus<CR>
map <Leader>gb :Gblame<CR>
map <Leader>gc :Gcommit<CR>
map <Leader>gp :Gpush<CR>
map <Leader>ga :Gwrite<CR>
map <Leader>d :e config/database.yml<CR>
map <Leader>a :A<CR>

"Remove search highlight
function! MapCR()
  nnoremap <CR> :nohlsearch<CR>
endfunction
call MapCR()

map <C-\> :e <CR>:exec("tag ".expand("<cword>"))<CR>
vmap <Enter> <Plug>(EasyAlign)
nmap k gk
nmap j gj

map <C-j> <C-W>j
map <C-k> <C-W>k

map <BS> <C-W>h
map <C-l> <C-W>l
map <Right> :bn<CR>
map <Left> :bp<CR>

noremap Y y$
noremap 0 ^

" Emacs-like beginning and end of line.
imap <c-e> <c-o>$
imap <c-a> <c-o>^

" Because I can't spell
cabbrev Wq wq
cabbrev WQ wq

nnoremap <C-N> :bnext<CR>
nnoremap <C-P> :bprev<CR>

"##############################################################################
"# AUTOCMDS
"##############################################################################

" Jump to last cursor position unless it's invalid or in an event handler
augroup vimrcEx
  autocmd!
  autocmd BufReadPost *
        \ if line("'\"") > 0 && line("'\"") <= line("$") |
        \ exe "normal g`\"" |
        \ endif

  "for ruby, autoindent with two spaces, always expand tabs
  autocmd FileType ruby,haml,eruby,yaml,fdoc,html,javascript,sass,cucumber set ai sw=2 sts=2 et

  autocmd BufNewFile,BufRead *.fdoc setfiletype yaml
  autocmd Filetype yaml set nocursorline
  autocmd BufNewFile,BufRead *.sass setfiletype sass
  autocmd Filetype markdown setlocal spell
augroup END

"" Remove trailing whitespace on save for ruby files.
autocmd BufWritePre *.rb :%s/\s\+$//e
autocmd BufWritePre *.js :%s/\s\+$//e

autocmd FileType gitcommit setlocal spell textwidth=72
autocmd FileType rust map <Leader>r :CargoRun<CR>
" autocmd BufWrite *.rs :Autoformat

"##############################################################################
"# PLUGIN SETTINGS
"##############################################################################

" YCM
let g:ycm_collect_identifiers_from_comments_and_strings = 1
let g:ycm_collect_identifiers_from_tags_files = 1
let g:ycm_complete_in_comments = 1

"replace 'f' with 1-char Sneak
nmap f <Plug>Sneak_f
nmap F <Plug>Sneak_F
xmap f <Plug>Sneak_f
xmap F <Plug>Sneak_F
omap f <Plug>Sneak_f
omap F <Plug>Sneak_F

"replace 't' with 1-char Sneak
nmap t <Plug>Sneak_t
nmap T <Plug>Sneak_T
xmap t <Plug>Sneak_t
xmap T <Plug>Sneak_T
omap t <Plug>Sneak_t
omap T <Plug>Sneak_T

" Grep
set grepprg=ag
let g:grep_cmd_opts = '--line-numbers --noheading'

" Testing settings
map <Leader>s :TestNearest<CR>
map <Leader>r :TestFile<CR>
" map <Leader>a :TestLast<CR>

function! SplitStrategy(cmd)
  botright new | call termopen(a:cmd) | startinsert
endfunction
let g:test#custom_strategies = {'terminal_split': function('SplitStrategy')}
let g:test#strategy = 'neoterm'

let g:neoterm_clear_cmd = "clear; printf '=%.0s' {1..80}; clear"
let g:neoterm_position = "horizontal"
let g:neoterm_automap_keys = ",tt"
let g:neoterm_split_on_tnew = 1
let g:neoterm_size = 25

let g:jsx_ext_required = 0
let g:used_javascript_libs = 'react,flux,chai'

" Use deoplete.
let g:deoplete#enable_at_startup = 1

function! s:line_handler(l)
  let keys = split(a:l, ':\t')
  exec 'buf' keys[0]
  exec keys[1]
  normal! ^zz
endfunction

function! s:buffer_lines()
  let res = []
  for b in filter(range(1, bufnr('$')), 'buflisted(v:val)')
    call extend(res, map(getbufline(b,0,"$"), 'b . ":\t" . (v:key + 1) . ":\t" . v:val '))
  endfor
  return res
endfunction

"##############################################################################
"# STOLEN SETTINGS FROM THE INTERWEBS
"##############################################################################

" Prevent Vim from clobbering the scrollback buffer. See
" http://www.shallowsky.com/linux/noaltscreen.html
set t_ti= t_te=
" keep more context when scrolling off the end of a buffer
set scrolloff=3
" Store temporary files in a central spot
set backup
set backupdir=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set directory=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp

" Rename current file
function! RenameFile()
  let old_name = expand('%')
  let new_name = input('New file name: ', expand('%'), 'file')
  if new_name != '' && new_name != old_name
    exec ':saveas ' . new_name
    exec ':silent !rm ' . old_name
    redraw!
  endif
endfunction
map <Leader>n :call RenameFile()<cr>

" Display extra whitespace
set list listchars=tab:»·,trail:·

" Make it more obvious which paren I'm on
hi MatchParen cterm=none ctermbg=black ctermfg=red

"##############################################################################
"# DEBUGGER HELPER
"##############################################################################
function! Debugging(direction)
  let file_name = expand('%')
  let extension = split(file_name, "/")[-1]
  let html = matchstr(extension, "html")
  let js = matchstr(extension, "js")

  let @g = a:direction

  if html == "html"
    normal! @g <% require "pry"; binding.pry %>
  elseif js == "js"
    normal! @g debugger;
  else
    normal! @g require "pry"; binding.pry
  endif
endfunction
map <Leader>P :call Debugging("O")<cr>
map <Leader>p :call Debugging("o")<cr>

"##############################################################################
"# PROMOTE VARIABLE TO RSPEC LET
"##############################################################################
function! PromoteToLet()
  :normal! dd
  " :exec '?^\s*it\>'
  :normal! P
  :.s/\(\w\+\) = \(.*\)$/let(:\1) { \2 }/
  :normal ==
endfunction
:command! PromoteToLet :call PromoteToLet()
:map <leader>sl :PromoteToLet<cr>
