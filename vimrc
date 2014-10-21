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
colorscheme gruvbox
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
let g:vroom_detect_spec_helper = 1
let g:vroom_use_spring = 1
let g:vroom_use_binstubs = 0
let g:vroom_cucumber_path = 'cucumber'

let g:rspec_command = "compiler rspec | set makeprg=zeus | Make rspec2 {spec}"
map <Leader>t :call RunCurrentSpecFile()<CR>

if executable('ag')
    " Use Ag over grep
    set grepprg=ag\ --nogroup\ --nocolor

    " Use ag in CtrlP
    let g:ctrlp_user_command = 'ag %s -l --nocolor -g ""'
    let g:ctrlp_use_caching = 0
endif

let g:ctrlp_match_window = 'bottom,order:btt,min:1,max:40'
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
set list listchars=tab:��,trail:�

" Make it more obvious which paren I'm on
hi MatchParen cterm=none ctermbg=black ctermfg=yellow


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
map <Leader>aa :CtrlP app/assets<CR>
map <Leader>ac :CtrlP app/controllers<CR>
map <Leader>ad :CtrlP db<CR>
map <Leader>af :CtrlP features<CR>
map <Leader>ag :topleft 20 :split Gemfile<CR>
map <Leader>ah :CtrlP app/helpers<CR>
map <Leader>ai :CtrlP app/services<CR>
map <Leader>aj :CtrlP app/jobs<CR>
map <Leader>al :CtrlP lib<CR>
map <Leader>am :CtrlP app/models<CR>
map <Leader>ap :CtrlP config<CR>
map <Leader>ar :topleft :split config/routes.rb<CR>
map <Leader>as :CtrlP spec/<CR>
map <Leader>av :CtrlP app/views<CR>
map <Leader>b :CtrlPBuffer<CR>
map <Leader>bi :!bundle install<cr>
map <Leader>c ::bp\|bd #<CR>
map <Leader>g :CtrlPMixed<CR>
map <Leader>kw :%s/\s\+$//<CR>
map <Leader>p Obinding.pry<C-c>
map <Leader>q :bd<CR>
map <Leader>sl 0wilet(:ea)f=r{A }<CR>
map <Leader>ss :CtrlP spec2/<CR>
map <Leader>t f f[a�kb.fetch(f]a�kb)<CR>
map <Leader>vi :tabe ~/.nvimrc<CR>
map <Leader>vs :source ~/.nvimrc<CR>
map <Leader>w :w!<CR>

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

