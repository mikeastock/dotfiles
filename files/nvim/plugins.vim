call plug#begin('~/.config/nvim/plugged')

"fuzzy finding
Plug 'junegunn/fzf', { 'dir': '~/.fzf', 'do': 'yes \| ./install' }
Plug 'junegunn/fzf.vim'

"looks
Plug 'itchyny/lightline.vim'

"Writing
Plug 'junegunn/goyo.vim'
Plug 'junegunn/limelight.vim'

"workflow
Plug 'tomtom/tcomment_vim'
Plug 'junegunn/vim-easy-align'
Plug 'pbrisbin/vim-mkdir'
Plug 'justinmk/vim-sneak'
Plug 'ap/vim-buftabline'
Plug 'kassio/neoterm'
Plug 'mcasper/vim-infer-debugger'
Plug 'airblade/vim-gitgutter'
Plug 'neomake/neomake'

"Autocomplete
Plug 'Valloric/YouCompleteMe'

" Langauge specific
Plug 'fatih/vim-go'
Plug 'pangloss/vim-javascript'
Plug 'mxw/vim-jsx'
Plug 'othree/javascript-libraries-syntax.vim'
Plug 'keith/swift.vim', { 'for': 'swift' }
Plug 'elixir-lang/vim-elixir', { 'for': 'elixir' }
Plug 'thinca/vim-ref', { 'for': 'elixir' }
Plug 'slashmili/alchemist.vim'
Plug 'vim-ruby/vim-ruby', { 'for': 'ruby' }
Plug 'ElmCast/elm-vim', { 'for': 'elm' }
Plug 'rust-lang/rust.vim'
Plug 'jtdowney/vimux-cargo'
Plug 'Keithbsmiley/rspec.vim'

"tpope
Plug 'tpope/vim-endwise'
Plug 'tpope/vim-rails'
Plug 'tpope/vim-fugitive'
Plug 'tpope/vim-surround'
" Plug 'tpope/vim-sleuth'

"testing
Plug 'janko-m/vim-test'

"colors
Plug 'nanotech/jellybeans.vim'
Plug 'morhetz/gruvbox'
Plug 'sjl/badwolf'
Plug 'chriskempson/base16-vim'
Plug 'flazz/vim-colorschemes'
Plug 'junegunn/seoul256.vim'

call plug#end()
