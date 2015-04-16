"
" Michael Stock's vimrc
"
" github.com/mikeastock/dotfiles
"

"Colorscheme settings
let g:gruvbox_italic=0

"==============
" Vundle setup
"==============
if filereadable(expand("~/.vimrc.bundles"))
  source ~/.vimrc.bundles
endif


"============================
" BASIC EDITING CONFIGURATION
"============================

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

"Color and UI
colorscheme spacegray
set background=dark
set colorcolumn=80
set cursorline
set ruler
set synmaxcol=250

"SPEEEEEEEEEEEEEED
set re=1

let mapleader = " "

"===============
"PLUGIN SETTINGS
"===============

map <Leader>s :TestNearest<CR>
map <Leader>r :TestFile<CR>
map <Leader>a :TestLast<CR>
" RSpec.vim mappings
" map <Leader>r :call RunCurrentSpecFile()<CR>
" map <Leader>s :call RunNearestSpec()<CR>
" map <Leader>l :call RunLastSpec()<CR>

" let g:rspec_command = "!bin/rspec {spec}"
" let g:rspec_command = 'call Send_to_Tmux("bin/rspec {spec}\n")'

" List of buffers
function! s:buflist()
  redir => ls
  silent ls
  redir END
  return split(ls, '\n')
endfunction

function! s:bufopen(e)
  execute 'buffer' matchstr(a:e, '^[ 0-9]*')
endfunction

nnoremap <silent> <Leader><Enter> :call fzf#run({
\   'source':  reverse(<sid>buflist()),
\   'sink':    function('<sid>bufopen'),
\   'options': '+m',
\   'down':    len(<sid>buflist()) + 2
\ })<CR>

if executable("ag")
  set grepprg=ag\ --nogroup\ --nocolor
  let g:ctrlp_user_command = 'ag %s -i --nocolor --nogroup --hidden
        \ --ignore .git
        \ --ignore .svn
        \ --ignore .hg
        \ --ignore .DS_Store
        \ --ignore node_modules
        \ -g ""'
endif

" PyMatcher for CtrlP
if !has('python')
  echo 'In order to use pymatcher plugin, you need +python compiled vim'
else
  let g:ctrlp_match_func = { 'match': 'pymatcher#PyMatch' }
endif

let g:ctrlp_match_window = 'bottom,order:btt,min:1,max:20'

" Do not clear filenames cache, to improve CtrlP startup
" You can manualy clear it by <F5>
" let g:ctrlp_clear_cache_on_exit = 0

" Set no file limit, we are building a big project
let g:ctrlp_max_files = 0

let g:neocomplcache_enable_at_startup = 1

"==================
"SETTINGS BY OTHERS
"==================

" Prevent Vim from clobbering the scrollback buffer. See
" http://www.shallowsky.com/linux/noaltscreen.html
set t_ti= t_te=
" keep more context when scrolling off the end of a buffer
set scrolloff=3
" Store temporary files in a central spot
set backup
set backupdir=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set directory=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp

"=================
"FROM r00k
"=================

"" Remove trailing whitespace on save for ruby files.
au BufWritePre *.rb :%s/\s\+$//e

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" RENAME CURRENT FILE (thanks Gary Bernhardt)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
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

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" DEBUGGING
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
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

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" PROMOTE VARIABLE TO RSPEC LET
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" map <Leader>sl 0wilet(:ea)f=r{A }<CR>
function! PromoteToLet()
  :normal! dd
  " :exec '?^\s*it\>'
  :normal! P
  :.s/\(\w\+\) = \(.*\)$/let(:\1) { \2 }/
  :normal ==
endfunction
:command! PromoteToLet :call PromoteToLet()
:map <leader>sl :PromoteToLet<cr>

"=========
"AUTOCMDS
"=========

augroup vimrcEx
  " Jump to last cursor position unless it's invalid or in an event handler
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

autocmd FileType gitcommit setlocal spell textwidth=72
autocmd BufRead,BufNewFile *.es6 setfiletype javascript

"===================
"KEY BINDINGS
"===================

"LEADER
map <Leader>ag :topleft 20 :split Gemfile<CR>
map <Leader>ar :topleft :split config/routes.rb<CR>
map <Leader>bi :!bundle install<cr>
map <Leader>c ::bp\|bd #<CR>
map <Leader>e :RuboCop<CR>
map <Leader>f :FZF<CR>
map <Leader>i :mmgg=G`m<CR>
map <Leader>kw :%s/\s\+$//<CR>
map <Leader>q :bd<CR>
map <Leader>t :terminal<CR>
map <Leader>rs :s/'/"<CR>
map <Leader>vi :tabe ~/.nvimrc<CR>
map <Leader>vs :source ~/.nvimrc<CR>
map <Leader>w :w!<CR>
map <Leader>hs :s/:\([^ ]*\)\(\s*\)=>/\1:/g<CR>
map <Leader>mi 0f:wywOit "pA" doj==oendkf{edi}Op==j0ftlvt.c(response)<CR>
nmap <Leader>gb :Gblame<CR>

" go specific leader mappings
au FileType go nmap <leader>r <Plug>(go-run)
au FileType go nmap <leader>b <Plug>(go-build)
au FileType go nmap <leader>t <Plug>(go-test)
au FileType go nmap <leader>c <Plug>(go-coverage)
au FileType go nmap <Leader>e <Plug>(go-rename)
au FileType go nmap <Leader>i <Plug>(go-info)

"OTHER
function! MapCR()
  nnoremap <CR> :nohlsearch<CR>
endfunction
call MapCR()

map <C-\> :tab split<CR>:exec("tag ".expand("<cword>"))<CR>
vmap <Enter> <Plug>(EasyAlign)
nmap k gk
nmap j gj
map <C-j> <C-W>j
map <C-k> <C-W>k
map <C-h> <C-W>h
map <C-l> <C-W>l
map <Right> :bn<CR>
map <Left> :bp<CR>

" Emacs-like beginning and end of line.
imap <c-e> <c-o>$
imap <c-a> <c-o>^
