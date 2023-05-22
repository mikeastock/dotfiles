--
-- init.vim
-- github.com/mikeastock/dotfiles
--

HOME = os.getenv("HOME")

-- HELPER FUNCTIONS
function map(mode, shortcut, command)
  vim.api.nvim_set_keymap(mode, shortcut, command, { noremap = true, silent = true })
end

function nmap(shortcut, command)
  map('n', shortcut, command)
end

function imap(shortcut, command)
  map('i', shortcut, command)
end

function vmap(shortcut, command)
  map('v', shortcut, command)
end

function cmap(shortcut, command)
  map('c', shortcut, command)
end

function tmap(shortcut, command)
  map('t', shortcut, command)
end

-- Plugins

local ensure_packer = function()
  local fn = vim.fn
  local install_path = fn.stdpath('data')..'/site/pack/packer/start/packer.nvim'
  if fn.empty(fn.glob(install_path)) > 0 then
    fn.system({'git', 'clone', '--depth', '1', 'https://github.com/wbthomason/packer.nvim', install_path})
    vim.cmd [[packadd packer.nvim]]
    return true
  end
  return false
end

local packer_bootstrap = ensure_packer()

require('packer').startup(function(use)
  -- Packer can manage itself
  use 'wbthomason/packer.nvim'

  -- fuzzy finding
  use {
    'junegunn/fzf.vim',
    requires = { 'junegunn/fzf', run = ':call fzf#install()' }
 }

  -- UI
  use 'itchyny/lightline.vim'

  -- workflow
  use 'AndrewRadev/splitjoin.vim'
  use 'FooSoft/vim-argwrap'
  use {
    'lewis6991/gitsigns.nvim',
    config = function()
      require('gitsigns').setup()
    end
  }
  use 'ap/vim-buftabline'
  use 'junegunn/vim-easy-align'
  use 'justinmk/vim-sneak'
  use 'mikeastock/vim-infer-debugger'
  use 'pbrisbin/vim-mkdir'
  use 'tpope/vim-abolish'
  use 'tpope/vim-commentary'
  use 'tpope/vim-dispatch'
  use 'tpope/vim-fugitive'
  use 'tpope/vim-surround'
  -- use 'mg979/vim-visual-multi', { 'branch': 'master' }
  -- use 'dense-analysis/ale'

  -- CSS Color Previews
  use {
    'norcalli/nvim-colorizer.lua',
    config = function()
      require('colorizer').setup()
    end
  }

  -- Text objects
  use {
    'andymass/vim-matchup',
    setup = function()
      -- may set any options here
      vim.g.matchup_matchparen_offscreen = { method = "popup" }
    end
  }

  -- Langauge specific

  -- JS
  use { 'HerringtonDarkholme/yats.vim', ft = 'typescript' }
  use {'othree/javascript-libraries-syntax.vim', ft = { 'javascript' }}
  use {'pangloss/vim-javascript', ft = { 'javascript' }}

  -- Ruby
  use {'Keithbsmiley/rspec.vim', ft = { 'ruby' }}
  use {'tpope/vim-rails', ft = { 'ruby' }}
  use {'vim-ruby/vim-ruby', ft = { 'ruby' }}

  -- Elixir
  use {'elixir-lang/vim-elixir', ft = { 'elixir,eelixir' }}
  use {'mhinz/vim-mix-format', ft = { 'elixir,eelixir' }}

  -- Misc
  use {'amadeus/vim-mjml', ft = { 'mjml' }}
  use {'andys8/vim-elm-syntax', ft = { 'elm' }}
  use {'dag/vim-fish', ft = { 'fish' }}
  use {'fatih/vim-go', ft = { 'golang' }}
  use {'hashivim/vim-terraform', ft = { 'terraform' }}
  use {'jvirtanen/vim-hcl', ft = { 'hcl' }}
  use {'rust-lang/rust.vim', ft = { 'rust' }}
  -- use {'cespare/vim-toml', { 'branch': 'main' }}

  -- -- Autocomplete
  -- use 'neoclide/coc.nvim', {'branch': 'release'}
  use 'github/copilot.vim'

  -- -- testing
  use 'vim-test/vim-test'
  use 'kassio/neoterm'

  -- colors
  -- use 'nanotech/jellybeans.vim'
  -- use 'morhetz/gruvbox'
  -- use 'sjl/badwolf'
  -- use 'chriskempson/base16-vim'
  -- use 'flazz/vim-colorschemes'
  -- use 'junegunn/seoul256.vim'
  -- use 'rakr/vim-one'
  use { "catppuccin/nvim", as = "catppuccin" }
end)


-- Tabs and spaces
vim.opt.tabstop = 2
vim.opt.shiftwidth = 2
vim.opt.softtabstop = 2
vim.opt.backspace = "indent,eol,start"
vim.opt.expandtab = true
vim.opt.autoindent = true
vim.opt.smarttab = true

-- Undo
vim.cmd([[
  if !isdirectory($HOME."/.config/nvim/undo-dir")
    call mkdir($HOME."/.config/nvim/undo-dir", "", 0700)
  endif
]])

vim.opt.undodir = HOME .. "/.config/nvim/undo-dir"
vim.opt.undofile = true


-- Misc
vim.cmd([[
set virtualedit=insert
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
set backup
set backupdir=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set directory=~/.vim-tmp,~/.tmp,~/tmp,/var/tmp,/tmp
set updatetime=250
set virtualedit=block
set tags+=./tags
set lazyredraw
set splitbelow
set splitright
set colorcolumn=80
set synmaxcol=250
set list
set listchars=tab:·\ ,trail:█
]])

vim.opt.mouse = "" -- I HATE MICE
vim.opt.gdefault = true -- Assume the /g flag on :s substitutions to replace all matches in a line
vim.opt.shiftround = true -- When at 3 spaces and I hit >>, go to 4, not 5.
vim.opt.showmode = false -- Hide -- INSERT -- in cmdline for echodoc

-- Color
vim.opt.termguicolors = true
vim.cmd.colorscheme "catppuccin-mocha" -- catppuccin-latte, catppuccin-frappe, catppuccin-macchiato, catppuccin-mocha

-- Color Preview
-- call v:lua.require('nvim-highlight-colors').setup({enable_named_colors = true, enable_tailwind = true})

-- syntax enable
-- highlight MatchParen ctermbg=black

vim.g.mapleader = " "

-- Leader Mappings
nmap("<Leader>f", "<cmd>Files<CR>")
nmap("<Leader>q", "<cmd>call CloseBuffer()<CR>")
nmap("<Leader>rs", "<cmd>%s/'/\"<CR>")
nmap("<Leader>vi", "<cmd>e ~/.config/nvim/init.lua<CR>")
nmap("<Leader>w", "<cmd>w!<CR>")
nmap("<Leader>gb", "<cmd>Git blame<CR>")
nmap("<Leader>l", "<cmd>Lines<CR>")
nmap("<Leader>P", "<cmd>call AddDebugger('O')<CR>")
nmap("<Leader>p", "<cmd>call AddDebugger('o')<CR>")

-- Force close current buffer
vim.cmd([[
function! CloseBuffer()
  if &buftype ==# 'terminal'
    :bd!
  else
    :bd
  endif
endfunction
]])

-- Remove search highlight
vim.cmd([[
function! MapCR()
  nnoremap <CR> :nohlsearch<CR>
endfunction
call MapCR()
]])

vmap("<Enter>", "<Plug>(EasyAlign)")

-- more natural movement with wrap on
nmap('j', 'gj')
nmap('k', 'gk')
vmap('j', 'gj')
vmap('k', 'gk')

-- Easy buffer navigation
nmap('<C-h>', '<C-w>h')
nmap('<C-j>', '<C-w>j')
nmap('<C-k>', '<C-w>k')
nmap('<C-l>', '<C-w>l')

nmap("K", "<cmd>Rg <C-R><C-W><CR>")

nmap("<Right>", "<cmd>bn<CR>")
nmap("<Left>", "<cmd>bp<CR>")

---- Because I can't spell
--cabbrev Wq wq
--cabbrev WQ wq
--cabbrev Qall qall
--cabbrev Wqall wqall

--##############################################################################
--# AUTOCMDS
--##############################################################################

vim.cmd("filetype plugin indent on")

vim.cmd([[
augroup indentation
  autocmd!
  autocmd BufReadPost *
        \ if line("'\"") > 0 && line("'\"") <= line("$") |
        \ exe "normal g`\"" |
        \ endif

  " for ruby, autoindent with two spaces, always expand tabs
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

au BufRead,BufNewFile *.star set filetype=python
]])

--##############################################################################
--# PLUGIN SETTINGS
--##############################################################################

----COC
---- inoremap <expr> <cr> pumvisible() ? "\<C-y>" : "\<C-g>u\<CR>"
---- inoremap <silent><expr> <cr> coc#pum#visible() ? coc#pum#confirm() : "\<cr>"
--inoremap <expr> <cr> coc#pum#visible() ? coc#_select_confirm() : "\<CR>"

---- nnoremap <nowait><expr> <C-f> coc#float#has_scroll() ? coc#float#scroll(1) : "\<C-f>"
---- nnoremap <nowait><expr> <C-b> coc#float#has_scroll() ? coc#float#scroll(0) : "\<C-b>"
---- inoremap <nowait><expr> <C-f> coc#float#has_scroll() ? "\<c-r>=coc#float#scroll(1)\<cr>" : "\<Right>"
---- inoremap <nowait><expr> <C-b> coc#float#has_scroll() ? "\<c-r>=coc#float#scroll(0)\<cr>" : "\<Left>"

--nmap <silent> gr <Plug>(coc-references)
--nmap <silent> <F3> <Plug>(coc-rename)
---- Find symbol of current document.
--nnoremap <silent><nowait> <space>o  :<C-u>CocList outline<cr>

--nmap <silent> <F2> <Plug>(coc-diagnostic-next)
---- nmap <silent> <leader>A <Plug>(coc-diagnostic-next-error)

---- " Do default action for next item.
---- nnoremap <silent><nowait> <space>j  :<C-u>CocNext<CR>
---- " Do default action for previous item.
---- nnoremap <silent><nowait> <space>k  :<C-u>CocPrev<CR>

--let g:coc_filetype_map = {
--  \ 'rspec.ruby': 'ruby',
--  \ }


----ArgWrap
nmap("<silent><Leader>a", "<cmd>ArgWrap<CR>")
vim.g.argwrap_tail_comma = true

--FZF
vim.cmd([[
let $FZF_DEFAULT_COMMAND = 'rg --hidden --glob "!**/.git/**" --files'

command! -bang -nargs=* Rg
  \ call fzf#vim#grep(
  \   'rg --column --line-number --no-heading --color=always --smart-case -- '.shellescape(<q-args>), 1,
  \   fzf#vim#with_preview(), <bang>0)
]])


-- Empty value to disable preview window altogether
vim.g.fzf_preview_window = false

-- Enable per-command history.
-- CTRL-N and CTRL-P will be automatically bound to next-history and
-- previous-history instead of down and up. If you don't like the change,
-- explicitly bind the keys to down and up in your $FZF_DEFAULT_OPTS.
vim.g.fzf_history_dir = HOME .. "/.local/share/fzf-history"

----Elixir
--let g:mix_format_on_save = 1

----Ale
---- let g:ale_disable_lsp = 1
---- let g:ale_lint_on_text_changed = 'never'
---- let g:ale_fix_on_save = 1
---- let g:ale_linters = {
----       \ 'eruby': ['erblint'],
----       \ 'ruby': ['rubocop'],
----       \}
---- let g:ale_fixers = {
----       \ 'eruby': ['erblint'],
----       \ 'ruby': ['rubocop'],
----       \}

----replace 'f' with 1-char Sneak
--nmap f <Plug>Sneak_f
--nmap F <Plug>Sneak_F
--xmap f <Plug>Sneak_f
--xmap F <Plug>Sneak_F
--omap f <Plug>Sneak_f
--omap F <Plug>Sneak_F

----replace 't' with 1-char Sneak
--nmap t <Plug>Sneak_t
--nmap T <Plug>Sneak_T
--xmap t <Plug>Sneak_t
--xmap T <Plug>Sneak_T
--omap t <Plug>Sneak_t
--omap T <Plug>Sneak_T

-- Testing settings
nmap("<Leader>s", ":TestNearest<CR>")
nmap("<Leader>t", ":TestNearest<CR>")
nmap("<Leader>T", ":TestFile<CR>")
nmap("<Leader>r", ":TestFile<CR>")

--let test#strategy = 'basic'
--let g:test#javascript#playwright#file_pattern = '\v(e2e/.*|(spec|test))\.(js|jsx|coffee|ts|tsx)$'

-- Useful maps
-- hide/close terminal
nmap("<Leader>th", ":call neoterm#close()<CR>")
-- clear terminal
nmap("<Leader>tl", ":call neoterm#clear()<CR>")

-- Make escape work in the Neovim terminal.
tmap("<Esc>", "<C-\\><C-n>")

-- I like relative numbering when in normal mode.
vim.cmd("autocmd TermOpen * setlocal conceallevel=0 colorcolumn=0 relativenumber")

--let g:user_debugger_dictionary = {
--      \ '\.rb': 'binding.irb',
--      \ }

-- Rename current file
vim.cmd([[
function! RenameFile()
  let old_name = expand('%')
  let new_name = input('New file name: ', expand('%'), 'file')
  if new_name != '' && new_name != old_name
    exec ':saveas ' . new_name
    exec ':silent !rm ' . old_name
    redraw!
  endif
endfunction
]])
nmap("<Leader>n", ":call RenameFile()<CR>")
