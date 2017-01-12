"
" Michael Stock's vimrc
"
" github.com/mikeastock/dotfiles
"

"##############################################################################
"# VIM PLUG SETUP
"##############################################################################
if filereadable(expand("~/.config/nvim/plugins.vim"))
  source ~/.config/nvim/plugins.vim
endif

"##############################################################################
"# BASIC EDITING CONFIGURATION
"##############################################################################

syntax enable
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
if (has("termguicolors"))
  set termguicolors
endif

colorscheme base16-default-dark
set background=dark

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
map <Leader>tp :T bundle exec rake db:test:prepare<cr>
map <Leader>f :FuzzyOpen<CR>
map <Leader>i mmgg=G`m<CR>
map <Leader>kw :%s/\s\+$//<CR>
map <Leader>q :call CloseBuffer()<CR>
map <Leader>bq :bd!<CR>
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
nmap <Leader>P :call AddDebugger("O")<CR>
nmap <Leader>p :call AddDebugger("o")<CR>

function! CloseBuffer()
  if &buftype ==# 'terminal'
    :bd!
  else
    :bd
  endif
endfunction

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

nnoremap K :FuzzyGrep <C-R><C-W><CR>

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
augroup other
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

  autocmd FileType swift set ai sw=4 sts=4 et

  autocmd FileType rust map <Leader>r :CargoRun<CR>
  autocmd FileType elm map <Leader>r :ElmMakeCurrentFile<CR>

  autocmd! BufWritePost * Neomake
augroup END

"" Remove trailing whitespace on save
augroup trailingWhitespace
  autocmd BufWritePre *.rb :%s/\s\+$//e
  autocmd BufWritePre *.ex :%s/\s\+$//e
  autocmd BufWritePre *.exs :%s/\s\+$//e
  autocmd BufWritePre *.js :%s/\s\+$//e
augroup END

augroup gitCommit
  autocmd FileType gitcommit setlocal spell textwidth=72
  autocmd FileType *.md setlocal spell textwidth=80
augroup END

"##############################################################################
"# PLUGIN SETTINGS
"##############################################################################

"YCM
let g:ycm_rust_src_path = '/usr/local/src/rust/src'

"FZF
let $FZF_DEFAULT_COMMAND = 'ag --hidden --ignore .git -g ""'
" let $FZF_DEFAULT_COMMAND='rg --files --no-ignore --hidden --follow --glob "!.git/*"'

let g:fzf_layout = { 'window': '-tabnew' }

" Mapping selecting mappings
nmap <leader><tab> <plug>(fzf-maps-n)
xmap <leader><tab> <plug>(fzf-maps-x)
omap <leader><tab> <plug>(fzf-maps-o)

" Insert mode completion
imap <c-x><c-k> <plug>(fzf-complete-word)
imap <c-x><c-f> <plug>(fzf-complete-path)
imap <c-x><c-j> <plug>(fzf-complete-file-ag)
imap <c-x><c-l> <plug>(fzf-complete-line)

"Goyo/Limelight
autocmd! User GoyoEnter Limelight
autocmd! User GoyoLeave Limelight!

"Elixir alchemist
let g:alchemist#elixir_erlang_src = "/usr/local/share/src"

"Elm
let g:elm_format_autosave = 1

"Neomake
let g:neomake_ruby_rdirty_maker = {
      \ 'exe': 'dirty',
      \ 'args': ['--format', 'emacs'],
      \ 'errorformat': '%f:%l:%c: %t: %m',
      \ 'postprocess': function('neomake#makers#ft#ruby#RubocopEntryProcess')
      \ }
let g:neomake_ruby_enabled_makers = ['mri', 'rdirty', 'reek', 'rubylint']

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
nnoremap <Leader>s :TestNearest<CR>
nnoremap <Leader>r :TestFile<CR>
nnoremap <Leader>a :TestLast<CR>

" Useful maps
" hide/close terminal
nnoremap <Leader>th :call neoterm#close()<CR>
" clear terminal
nnoremap <Leader>tl :call neoterm#clear()<CR>
" kills the current job (send a <c-c>)
nnoremap <Leader>tc :call neoterm#kill()<CR>

let g:test#strategy = 'neoterm'

let g:neoterm_clear_cmd = "clear; printf '=%.0s' {1..80}; clear"
let g:neoterm_position = "horizontal"
let g:neoterm_automap_keys = ",tt"
let g:neoterm_split_on_tnew = 1
let g:neoterm_size = 20

let g:jsx_ext_required = 0
let g:used_javascript_libs = 'react,flux,chai'

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
