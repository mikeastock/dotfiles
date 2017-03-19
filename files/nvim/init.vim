"
" vimrc
" github.com/mikeastock/dotfiles
"

" PLugins
if filereadable(expand("~/.config/nvim/plugins.vim"))
  source ~/.config/nvim/plugins.vim
endif

" Tabs and spaces
set tabstop=2
set shiftwidth=2
set softtabstop=2
set backspace=indent,eol,start
set expandtab
set autoindent
set smarttab

" Misc
set number
set relativenumber
set ruler
set wildmenu
set wildmode=longest,list,full
set wrap
set breakindent
set hidden
set hlsearch
set autoread
set ignorecase
set smartcase
set report=0
set laststatus=2
set cursorline
set scrolloff=4
set nofoldenable
set timeoutlen=500
set mouse="" " I HATE MICE
set backup
set backupdir=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set directory=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set updatetime=250
set virtualedit=block
set tags+=./tags
set gdefault " Assume the /g flag on :s substitutions to replace all matches in a line
set lazyredraw
set splitbelow
set splitright
set shiftround " When at 3 spaces and I hit >>, go to 4, not 5.
set colorcolumn=80
set synmaxcol=250
set list
set listchars=tab:·\ ,trail:█

" Color
set termguicolors

if $LIGHT_SHELL
  "Light
  set background=light
  colorscheme gruvbox
else
  " "Dark
  set background=dark
  colorscheme gruvbox
endif

syntax enable
highlight MatchParen ctermbg=black

runtime macros/matchit.vim " Enabled matchit for Ruby text objects

let mapleader = "\<Space>"

let $NVIM_TUI_ENABLE_CURSOR_SHAPE=1

" Deoplete (autocomplete)
let g:deoplete#enable_at_startup = 0
let g:deoplete#disable_auto_complete = 1
let g:deoplete#enable_smart_case = 1

let g:monster#completion#rcodetools#backend = "async_rct_complete"
let g:deoplete#sources#omni#input_patterns = {
\   "ruby" : '[^. *\t]\.\w*\|\h\w*::',
\}

inoremap <silent><expr> <TAB>
  \ pumvisible() ? "\<C-n>" :
  \ <SID>check_back_space() ? "\<TAB>" :
  \ deoplete#mappings#manual_complete()
function! s:check_back_space()
  let col = col('.') - 1
  return !col || getline('.')[col - 1]  =~ '\s'
endfunction

" Leader Mappings
map <Leader>f :Files<CR>
map <Leader>a :Rg!<CR>
map <Leader>i mmgg=G`m<CR>
map <Leader>kw :%s/\s\+$//<CR>
map <Leader>q :call CloseBuffer()<CR>
map <Leader>bq :bd!<CR>
map <Leader>rs :%s/'/"<CR>
map <Leader>vi :e ~/.config/nvim/init.vim<CR>
map <Leader>w :w!<CR>
map <Leader>hs :%s/:\([^ ]*\)\(\s*\)=>/\1:/<CR>
map <Leader>mi 0f:wywOit "pA" doj==oendkf{edi}Op==j0ftlvt.c(response)<CR>
map <Leader>gs :Gstatus<CR>
map <Leader>gb :Gblame<CR>
map <Leader>gc :Gcommit<CR>
map <Leader>gp :Gpush<CR>
map <Leader>ga :Gwrite<CR>
map <Leader>d :e config/database.yml<CR>
map <Leader>l :Lines<CR>
map <Leader>t :Tags<CR>
nmap <Leader>P :call AddDebugger("O")<CR>
nmap <Leader>p :call AddDebugger("o")<CR>

" Force close current buffer
function! CloseBuffer()
  if &buftype ==# 'terminal'
    :bd!
  else
    :bd
  endif
endfunction

" Remove search highlight
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

nnoremap K :Rg <C-R><C-W><CR>

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

filetype plugin indent on

augroup indentation
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
augroup END

augroup neomake_cmds
  autocmd BufWritePost * Neomake
  autocmd BufWritePost *.rs Neomake! cargocheck
augroup END

" Remove trailing whitespace on save
augroup trailingWhitespace
  autocmd BufWritePre * :%s/\s\+$//e
augroup END

augroup gitCommit
  autocmd FileType gitcommit setlocal spell textwidth=72
  autocmd FileType *.md setlocal spell textwidth=80
augroup END

"##############################################################################
"# PLUGIN SETTINGS
"##############################################################################

"Racer
let g:rustfmt_autosave = 0
let g:racer_cmd = "~/.cargo/bin/racer"
let g:racer_experimental_completer = 1
let $RUST_SRC_PATH= "/usr/local/src/rust"

au FileType rust nmap gd <Plug>(rust-def)
au FileType rust nmap gs <Plug>(rust-def-split)
au FileType rust nmap gx <Plug>(rust-def-vertical)
au FileType rust nmap <leader>gd <Plug>(rust-doc)

"FZF
let $FZF_DEFAULT_COMMAND = 'ag --hidden --ignore .git -g ""'

" Enable per-command history.
" CTRL-N and CTRL-P will be automatically bound to next-history and
" previous-history instead of down and up. If you don't like the change,
" explicitly bind the keys to down and up in your $FZF_DEFAULT_OPTS.
let g:fzf_history_dir = '~/.local/share/fzf-history'

" Similarly, we can apply it to fzf#vim#grep. To use ripgrep instead of ag:
command! -bang -nargs=* Rg
  \ call fzf#vim#grep(
  \   'rg --column --line-number --no-heading --color=always '.shellescape(<q-args>), 1,
  \   <bang>0 ? fzf#vim#with_preview('up:60%')
  \           : fzf#vim#with_preview('right:50%:hidden', '?'),
  \   <bang>0)

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
let g:neomake_ruby_enabled_makers = ['mri', 'rdirty']
let g:neomake_rust_enabled_makers = []

let g:neomake_cargocheck_maker = {
      \ 'exe': 'cargo',
      \ 'args': ['check'],
      \ 'errorformat':
      \ neomake#makers#ft#rust#rustc()['errorformat'],
      \ }

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

" Testing settings
nnoremap <Leader>s :TestNearest<CR>
nnoremap <Leader>r :TestFile<CR>

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

"##############################################################################
"# PROMOTE VARIABLE TO RSPEC LET
"##############################################################################
function! PromoteToLet()
  normal! dd
  exec '?^\s*it\>'
  normal! P
  .s/\(\w\+\) = \(.*\)$/let(:\1) { \2 }/
  normal ==
endfunction
command! PromoteToLet :call PromoteToLet()
noremap <leader>sl :PromoteToLet<cr>
