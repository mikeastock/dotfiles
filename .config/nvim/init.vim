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
set noshowmode " Hide -- INSERT -- in cmdline for echodoc

" Color
set termguicolors

if filereadable(expand("~/.vimrc_background"))
  let base16colorspace=256
  source ~/.vimrc_background
endif

syntax enable
highlight MatchParen ctermbg=black

runtime macros/matchit.vim " Enabled matchit for Ruby text objects

let mapleader = "\<Space>"

" Leader Mappings
map <Leader>f :Files<CR>
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
" map <Leader>t :Tags<CR>
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

map <C-h> <C-W>h
map <C-l> <C-W>l
map <C-j> <C-W>j
map <C-k> <C-W>k

nnoremap K :Rg <C-R><C-W><CR>

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
cabbrev Qall qall
cabbrev Wqall wqall

nnoremap <C-P> :Files<CR>

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

  autocmd BufNewFile,BufRead Fastfile setfiletype ruby
  autocmd BufNewFile,BufRead *.fdoc setfiletype yaml
  autocmd Filetype yaml set nocursorline
  autocmd BufNewFile,BufRead *.sass setfiletype sass
  autocmd Filetype markdown setlocal spell
  autocmd FileType swift set ai sw=4 sts=4 et
augroup END

augroup elm
  autocmd FileType elm map <Leader>t ElmTest<CR>
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

"COC
inoremap <expr> <cr> pumvisible() ? "\<C-y>" : "\<C-g>u\<CR>"

"ArgWrap
nnoremap <silent><Leader>a :ArgWrap<CR>
let g:argwrap_tail_comma = 1

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

"Elixir
let g:mix_format_on_save = 1

"Elm
let g:elm_format_autosave = 1

"Ale
let g:ale_lint_on_text_changed = 'never'
let g:ale_fix_on_save = 1
let g:ale_linters = {
      \ 'elixir': [],
      \ 'rust': ['rls'],
      \ 'ruby': ['rubocop']
      \}
let g:ale_fixers = {
      \ 'ruby': ['rubocop']
      \}

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
nnoremap <Leader>t :TestNearest<CR>
nnoremap <Leader>T :TestFile<CR>
nnoremap <Leader>r :TestFile<CR>

" Useful maps
" hide/close terminal
nnoremap <Leader>th :call neoterm#close()<CR>
" clear terminal
nnoremap <Leader>tl :call neoterm#clear()<CR>
" kills the current job (send a <c-c>)
nnoremap <Leader>tc :call neoterm#kill()<CR>

" Make escape work in the Neovim terminal.
tnoremap <Esc> <C-\><C-n>

" I like relative numbering when in normal mode.
autocmd TermOpen * setlocal conceallevel=0 colorcolumn=0 relativenumber

let test#strategy = 'basic'

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
