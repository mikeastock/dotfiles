"
" Michael Stock's vimrc
"
" github.com/mikeastock/dotfiles
"

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

colorscheme jellybeans
set colorcolumn=80
set cursorline
set ruler
set synmaxcol=200

if executable('ag')
    " Use Ag over grep
    set grepprg=ag\ --nogroup\ --nocolor

    " Use ag in CtrlP
    let g:ctrlp_user_command = 'ag %s -l --nocolor -g ""'
    let g:ctrlp_use_caching = 0
endif

let mapleader = " "

if !empty($TMUX)
  let &t_SI = "\<Esc>Ptmux;\<Esc>\<Esc>]50;CursorShape=1\x7\<Esc>\\"
  let &t_EI = "\<Esc>Ptmux;\<Esc>\<Esc>]50;CursorShape=0\x7\<Esc>\\"
endif

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
augroup END

autocmd FileType gitcommit setlocal spell textwidth=72

"===================
"KEY BINDINGS
"===================

"LEADER 
map <Leader>w :w!<CR>
map <Leader>q :bd<CR>
map <Leader>ar :topleft :split config/routes.rb<cr>
map <Leader>aa :CtrlP app<cr>
map <Leader>av :CtrlP app/views<cr>
map <Leader>ac :CtrlP app/controllers<cr>
map <Leader>am :CtrlP app/models<cr>
map <Leader>ah :CtrlP app/helpers<cr>
map <Leader>ai :CtrlP app/serializers<cr>
map <Leader>as :CtrlP spec/<cr>
map <Leader>ss :CtrlP spec2/<cr>
map <Leader>al :CtrlP lib<cr>
map <Leader>ap :CtrlP config<cr>
map <Leader>af :CtrlP features<cr>
map <Leader>ad :CtrlP docs<cr>
map <Leader>ag :topleft 20 :split Gemfile<cr>
map <Leader>g :CtrlPMixed<cr>
map <Leader>b :CtrlPBuffer<cr>
map <Leader>p Obinding.pry<C-c>

"OTHER
function! MapCR()
    nnoremap <cr> :nohlsearch<cr>
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
