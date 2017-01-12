call plug#begin('~/.config/nvim/plugged')

"fuzzy finding
Plug 'cloudhead/neovim-fuzzy'

"looks
Plug 'itchyny/lightline.vim'

"workflow
Plug 'junegunn/vim-easy-align'
Plug 'pbrisbin/vim-mkdir'
Plug 'justinmk/vim-sneak'
Plug 'ap/vim-buftabline'
Plug 'mcasper/vim-infer-debugger'
Plug 'airblade/vim-gitgutter'
Plug 'neomake/neomake'
Plug 'tpope/vim-endwise'
Plug 'tpope/vim-fugitive'
Plug 'tpope/vim-surround'
Plug 'tpope/vim-commentary'

"Autocomplete
Plug 'Valloric/YouCompleteMe'

" Langauge specific
Plug 'fatih/vim-go', { 'for': 'golang' }
Plug 'pangloss/vim-javascript', { 'for': 'javascript' }
Plug 'mxw/vim-jsx', { 'for': 'javascript' }
Plug 'othree/javascript-libraries-syntax.vim', { 'for': 'javascript' }
Plug 'keith/swift.vim', { 'for': 'swift' }
Plug 'elixir-lang/vim-elixir', { 'for': 'elixir' }
Plug 'slashmili/alchemist.vim', { 'for': 'elixir' }
Plug 'vim-ruby/vim-ruby', { 'for': 'ruby' }
Plug 'Keithbsmiley/rspec.vim', { 'for': 'ruby' }
Plug 'tpope/vim-rails', { 'for': 'ruby' }
Plug 'ElmCast/elm-vim', { 'for': 'elm' }
Plug 'rust-lang/rust.vim', { 'for': 'rust' }

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

call plug#end()
