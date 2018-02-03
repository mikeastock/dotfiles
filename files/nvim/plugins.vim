call plug#begin('~/.config/nvim/plugged')

"fuzzy finding
Plug 'junegunn/fzf', { 'dir': '~/.fzf', 'do': './install --all' }
Plug 'junegunn/fzf.vim'

"looks
Plug 'itchyny/lightline.vim'

"workflow
Plug 'AndrewRadev/splitjoin.vim'
Plug 'airblade/vim-gitgutter'
Plug 'ap/vim-buftabline'
Plug 'foosoft/vim-argwrap'
Plug 'junegunn/vim-easy-align'
Plug 'justinmk/vim-sneak'
Plug 'mcasper/vim-infer-debugger'
Plug 'pbrisbin/vim-mkdir'
Plug 'tpope/vim-abolish'
Plug 'tpope/vim-commentary'
Plug 'tpope/vim-dispatch'
Plug 'tpope/vim-endwise'
Plug 'tpope/vim-fugitive'
Plug 'tpope/vim-surround'
Plug 'w0rp/ale'

"Text objects
Plug 'kana/vim-textobj-user', { 'for': 'ruby' }
Plug 'nelstrom/vim-textobj-rubyblock', { 'for': 'ruby' }

" Langauge specific
Plug 'fatih/vim-go', { 'for': 'golang' }
Plug 'pangloss/vim-javascript', { 'for': 'javascript' }
Plug 'mxw/vim-jsx', { 'for': 'javascript' }
Plug 'othree/javascript-libraries-syntax.vim', { 'for': 'javascript' }
Plug 'keith/swift.vim', { 'for': 'swift' }
Plug 'elixir-lang/vim-elixir', { 'for': 'elixir,eelixir' }
Plug 'slashmili/alchemist.vim', { 'for': 'elixir' }
Plug 'vim-ruby/vim-ruby', { 'for': 'ruby' }
Plug 'Keithbsmiley/rspec.vim', { 'for': 'ruby' }
Plug 'tpope/vim-rails', { 'for': 'ruby' }
Plug 'ElmCast/elm-vim', { 'for': 'elm' }
Plug 'rust-lang/rust.vim', { 'for': 'rust' }
Plug 'rodjek/vim-puppet', { 'for': 'puppet' }
Plug 'hashivim/vim-terraform', { 'for': 'terraform' }
Plug 'dag/vim-fish', { 'for': 'fish' }
Plug 'mhinz/vim-mix-format', { 'for': 'elixir' }

"Autocomplete
Plug 'Shougo/deoplete.nvim', { 'do': ':UpdateRemotePlugins' }
Plug 'racer-rust/vim-racer'

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
