call plug#begin('~/.vim/plugged')

" Plug 'kana/vim-textobj-user'
" Plug 'nelstrom/vim-textobj-rubyblock'
" Plug 'ecomba/vim-ruby-refactoring'

"fuzzy finding
Plug 'junegunn/fzf', { 'dir': '~/.fzf', 'do': 'yes \| ./install' }
Plug 'junegunn/fzf.vim'

Plug 'rking/ag.vim'

"looks
Plug 'ervandew/supertab'
Plug 'itchyny/lightline.vim'

"Writing
Plug 'junegunn/goyo.vim'
Plug 'junegunn/limelight.vim'

"workflow
Plug 'tomtom/tcomment_vim'
Plug 'junegunn/vim-easy-align'
Plug 'tmhedberg/matchit'
Plug 'pbrisbin/vim-mkdir'
Plug 'justinmk/vim-sneak'
Plug 'ap/vim-buftabline'
Plug 'kassio/neoterm'
Plug 'mcasper/vim-infer-debugger'
" Plug 'jiangmiao/auto-pairs'
" Plug 'ngmy/vim-rubocop'
" Plug 'Raimondi/delimitMate'
" Plug 'AndrewRadev/splitjoin.vim'

"Autocomplete
Plug 'Shougo/deoplete.nvim'
Plug 'Shougo/neoinclude.vim'

"langauge specific
Plug 'fatih/vim-go'
Plug 'derekwyatt/vim-scala'
Plug 'pangloss/vim-javascript'
Plug 'mxw/vim-jsx'
Plug 'othree/javascript-libraries-syntax.vim'
Plug 'elixir-lang/vim-elixir'
Plug 'awetzel/elixir.nvim', { 'do': 'yes \| ./install.sh' }

"Rust
Plug 'rust-lang/rust.vim'
Plug 'jtdowney/vimux-cargo'
Plug 'Chiel92/vim-autoformat'
" Plug 'racer-rust/vim-racer'

"tpope
Plug 'tpope/vim-endwise'
Plug 'tpope/vim-rails'
Plug 'tpope/vim-fugitive'
Plug 'tpope/vim-surround'
Plug 'tpope/vim-fireplace', { 'for': 'clojure' }
" Plug 'tpope/vim-sleuth'

"testing
Plug 'janko-m/vim-test'

"colors
Plug 'ajh17/Spacegray.vim'
Plug 'nanotech/jellybeans.vim'
Plug 'ChrisKempson/Vim-Tomorrow-Theme'
Plug 'morhetz/gruvbox'
Plug 'Keithbsmiley/rspec.vim'
Plug 'sjl/badwolf'
Plug 'jpo/vim-railscasts-theme'
Plug 'chriskempson/base16-vim'
Plug 'flazz/vim-colorschemes'
Plug 'gilgigilgil/anderson.vim'
Plug 'junegunn/seoul256.vim'

call plug#end()
