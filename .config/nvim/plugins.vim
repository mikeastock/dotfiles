call plug#begin('~/.config/nvim/plugged')

"fuzzy finding
Plug 'junegunn/fzf', { 'dir': '~/.fzf', 'do': './install --all' }
Plug 'junegunn/fzf.vim'

"looks
Plug 'itchyny/lightline.vim'

"workflow
"Plug 'tpope/vim-endwise'
Plug 'AndrewRadev/splitjoin.vim'
Plug 'FooSoft/vim-argwrap'
Plug 'airblade/vim-gitgutter'
Plug 'ap/vim-buftabline'
Plug 'junegunn/vim-easy-align'
Plug 'justinmk/vim-sneak'
Plug 'mcasper/vim-infer-debugger'
Plug 'pbrisbin/vim-mkdir'
Plug 'terryma/vim-multiple-cursors'
Plug 'tpope/vim-abolish'
Plug 'tpope/vim-commentary'
Plug 'tpope/vim-dispatch'
Plug 'tpope/vim-fugitive'
Plug 'tpope/vim-surround'
Plug 'w0rp/ale'

"Text objects
Plug 'kana/vim-textobj-user', { 'for': 'ruby' }
Plug 'nelstrom/vim-textobj-rubyblock', { 'for': 'ruby' }

" Langauge specific
Plug 'ElmCast/elm-vim', { 'for': 'elm' }
Plug 'HerringtonDarkholme/yats.vim'
Plug 'Keithbsmiley/rspec.vim', { 'for': 'ruby' }
Plug 'dag/vim-fish', { 'for': 'fish' }
Plug 'elixir-lang/vim-elixir', { 'for': 'elixir,eelixir' }
Plug 'fatih/vim-go', { 'for': 'golang' }
Plug 'hashivim/vim-terraform', { 'for': 'terraform' }
Plug 'jparise/vim-graphql'
Plug 'keith/swift.vim', { 'for': 'swift' }
Plug 'mhinz/vim-mix-format', { 'for': 'elixir,eelixir' }
Plug 'mxw/vim-jsx', { 'for': 'javascript' }
Plug 'othree/javascript-libraries-syntax.vim', { 'for': 'javascript' }
Plug 'pangloss/vim-javascript', { 'for': 'javascript' }
Plug 'rodjek/vim-puppet', { 'for': 'puppet' }
Plug 'rust-lang/rust.vim', { 'for': 'rust' }
Plug 'tpope/vim-rails', { 'for': 'ruby' }
Plug 'vim-ruby/vim-ruby', { 'for': 'ruby' }

"Autocomplete
Plug 'neoclide/coc.nvim', {'branch': 'release'}

"testing
Plug 'janko-m/vim-test'
Plug 'kassio/neoterm'

"colors
Plug 'nanotech/jellybeans.vim'
Plug 'morhetz/gruvbox'
Plug 'sjl/badwolf'
Plug 'chriskempson/base16-vim'
Plug 'flazz/vim-colorschemes'
Plug 'junegunn/seoul256.vim'
Plug 'rakr/vim-one'

call plug#end()
