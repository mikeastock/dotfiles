"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"Michael Stock's vimrc -- http://github.com/mikeastock/dotfiles
"Last updated 01/27/2014

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" VUNDLE
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
if filereadable(expand("~/.vimrc.bundles"))
  source ~/.vimrc.bundles
endif

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" BASIC EDITING CONFIGURATION
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" set encoding for airplane
set encoding=utf-8
" allow unsaved background buffers and remember marks/undo for them
set hidden
" remember more commands and search history
set history=10000
set expandtab
set tabstop=2
set shiftwidth=2
set softtabstop=2
set autoindent
set laststatus=2
set showmatch
set incsearch
set hlsearch
" make searches case-sensitive only if they contain upper-case characters
set ignorecase smartcase
" highlight current line
set cursorline
"Always show current position
set ruler
set number
set cmdheight=2
set switchbuf=useopen
set numberwidth=6
set showtabline=2
set winwidth=90
set tags=tags;/ 
set colorcolumn=80
" Prevent Vim from clobbering the scrollback buffer. See
" http://www.shallowsky.com/linux/noaltscreen.html
set t_ti= t_te=
" keep more context when scrolling off the end of a buffer
set scrolloff=3
" Store temporary files in a central spot
set backup
set backupdir=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set directory=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
" allow backspacing over everything in insert mode
set backspace=indent,eol,start
" display incomplete commands
set showcmd
" Enable highlighting for syntax
syntax on
" Enable file type detection.
" Use the default filetype settings, so that mail gets 'tw' set to 72,
" 'cindent' is on in C files, etc.
" Also load indent files, to automatically do language-dependent indenting.
filetype plugin indent on
" use emacs-style tab completion when selecting files, etc
set wildmode=longest,list
" make tab completion for files/buffers act like bash
set wildmenu
let mapleader = " "

nnoremap <Leader>e :vertical wincmd f<CR>

"ctags custom mappings
map <C-\> :tab split<CR>:exec("tag ".expand("<cword>"))<CR>
map <C-]> :vsp <CR>:exec("tag ".expand("<cword>"))<CR>

"vim ruby commands
imap <S-CR> <CR><CR>end<Esc>-cc

" Start interactive EasyAlign in visual mode
vmap <Enter> <Plug>(EasyAlign)
"
" Start interactive EasyAlign with a Vim movement
nmap <Leader>a <Plug>(EasyAlign)

" Resize panes
nnoremap <silent> <Leader>+ :exe "resize " . (winheight(0) * 3/2)<CR>
nnoremap <silent> <Leader>- :exe "resize " . (winheight(0) * 2/3)<CR>

" Open new splits to right and below
set splitbelow
set splitright

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" CUSTOM AUTOCMDS
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
augroup vimrcEx
" Jump to last cursor position unless it's invalid or in an event handler
  autocmd!
  autocmd BufReadPost *
    \ if line("'\"") > 0 && line("'\"") <= line("$") |
    \ exe "normal g`\"" |
    \ endif
        
    "for ruby, autoindent with two spaces, always expand tabs
    autocmd FileType ruby,haml,eruby,yaml,html,javascript,sass,cucumber set ai sw=2 sts=2 et

    autocmd BufRead, BufNewFile *.sass setfiletype sass
augroup END

autocmd FileType gitcommit setlocal spell textwidth=72

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" COLOR
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"set guioptions-=T
set t_Co=256 " 256 colors
set background=dark
colorscheme jellybeans

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Airline
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"let g:airline#extensions#tabline#enabled = 1
" let g:airline_powerline_fonts = 1
let g:bufferline_echo = 0

if !exists('g:airline_symbols')
    let g:airline_symbols = {}
endif

" unicode symbols
let g:airline_left_sep = '»'
let g:airline_left_sep = '▶'
let g:airline_right_sep = '«'
let g:airline_right_sep = '◀'
let g:airline_symbols.linenr = '␊'
let g:airline_symbols.linenr = '␤'
let g:airline_symbols.linenr = '¶'
let g:airline_symbols.branch = '⎇'
let g:airline_symbols.paste = 'ρ'
let g:airline_symbols.paste = 'Þ'
let g:airline_symbols.paste = '∥'
let g:airline_symbols.whitespace = 'Ξ'

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" MISC KEY MAPS
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Fast saving
nmap <leader>w :w!<cr>
" Fast buffer closing
nmap <leader>q :bd<cr>
" Fast vim closing
nnoremap <leader>qq :q<cr>
" Switch back to previous file
nnoremap <leader><leader> <c-^>
" NERDTREE toggle
nnoremap <leader>t :NERDTreeToggle<CR>
" Smart way to move btw. windows
map <C-j> <C-W>j
map <C-k> <C-W>k
map <C-h> <C-W>h
map <C-l> <C-W>l
" Line wrapping
nmap k gk
nmap j gj
" Usg the arrows to something usefull
map <right> :bn<cr>
map <left> :bp<cr>
" Control-C to return to Command Mode
imap <c-c> <esc>
" Clear the search buffer when hitting return
function! MapCR()
    nnoremap <cr> :nohlsearch<cr>
endfunction
call MapCR()
"binding.pry remote
nnoremap <leader>p :execute "normal Obinding.pry"<CR>
nnoremap <leader>v :execute "normal O<% binding.pry  %>"<CR>
" Don't add the comment prefix when I hit enter or o/O on a comment line.
set formatoptions-=or

" Merge a tab into a split in the previous window
function! MergeTabs()
  if tabpagenr() == 1
    return
  endif
  let bufferName = bufname("%")
  if tabpagenr("$") == tabpagenr()
    close!
  else
    close!
    tabprev
  endif
  split
  execute "buffer " . bufferName
endfunction

nmap <C-W>u :call MergeTabs()<CR>

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" CTRLP
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
if executable('ag')
    " Use Ag over grep
    set grepprg=ag\ --nogroup\ --nocolor

    " Use ag in CtrlP
    let g:ctrlp_user_command = 'ag %s -l --nocolor -g ""'
    let g:ctrlp_use_caching = 0
endif

" let g:ctrlp_working_path_mode = 'rc'
let g:ctrlp_max_height = 30
" let g:ctrlp_working_path_mode = 0

set wildignore+=tags
set wildignore+=*/tmp/*
set wildignore+=*/vendor/*
set wildignore+=*/spec/vcr/*
set wildignore+=*/public/*
set wildignore+=*/chef/*
set wildignore+=*/coverage/*
set wildignore+=*.png,*.jpg,*.otf,*.woff,*.jpeg,*.orig

map <leader>gr :topleft :split config/routes.rb<cr>
map <leader>gv :CtrlP app/views<cr>
map <leader>gc :CtrlP app/controllers<cr>
map <leader>gm :CtrlP app/models<cr>
map <leader>gh :CtrlP app/helpers<cr>
map <leader>gs :CtrlP spec/<cr>
map <leader>gl :CtrlP lib<cr>
map <leader>gp :CtrlP config<cr>
map <leader>gf :CtrlP features<cr>
map <leader>gg :topleft 20 :split Gemfile<cr>
map <leader>f :CtrlPMixed<cr>
map <leader>b :CtrlPBuffer<cr>

let g:CtrlMaxFiles=40000


"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" => Files and backups
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Turn backup off, since most stuff is in SVN, git anyway...
set nobackup
set nowb
set noswapfile


"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" VROOM
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
let g:vroom_detect_spec_helper = 1
let g:vroom_use_spring = 1
let g:vroom_use_binstubs = 1
let g:vroom_cucumber_path = 'cucumber'

