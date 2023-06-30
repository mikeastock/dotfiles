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
  local install_path = fn.stdpath('data') .. '/site/pack/packer/start/packer.nvim'
  if fn.empty(fn.glob(install_path)) > 0 then
    fn.system({ 'git', 'clone', '--depth', '1', 'https://github.com/wbthomason/packer.nvim', install_path })
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
    'ibhagwan/fzf-lua',
    requires = { 'nvim-tree/nvim-web-devicons' },
  }

  -- UI
  use {
    'nvim-lualine/lualine.nvim',
    requires = { 'nvim-tree/nvim-web-devicons' },
  }

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

  -- CSS Color Previews
  use {
    'norcalli/nvim-colorizer.lua',
    config = function()
      require('colorizer').setup()
    end
  }

  -- Text objects
  -- use {
  --   'nvim-treesitter/nvim-treesitter',
  -- }

  -- use {
  --   "nvim-treesitter/nvim-treesitter-textobjects",
  --   after = "nvim-treesitter",
  --   requires = "nvim-treesitter/nvim-treesitter",
  -- }

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
  use { 'othree/javascript-libraries-syntax.vim', ft = { 'javascript' } }
  use { 'pangloss/vim-javascript', ft = { 'javascript' } }

  -- Ruby
  use { 'Keithbsmiley/rspec.vim', ft = { 'ruby' } }
  use { 'tpope/vim-rails', ft = { 'ruby' } }
  use { 'vim-ruby/vim-ruby', ft = { 'ruby' } }

  -- Elixir
  use { 'elixir-lang/vim-elixir', ft = { 'elixir,eelixir' } }
  use { 'mhinz/vim-mix-format', ft = { 'elixir,eelixir' } }

  -- Misc
  use { 'amadeus/vim-mjml', ft = { 'mjml' } }
  use { 'andys8/vim-elm-syntax', ft = { 'elm' } }
  use { 'dag/vim-fish', ft = { 'fish' } }
  use { 'fatih/vim-go', ft = { 'golang' } }
  use { 'hashivim/vim-terraform', ft = { 'terraform' } }
  use { 'jvirtanen/vim-hcl', ft = { 'hcl' } }
  use { 'rust-lang/rust.vim', ft = { 'rust' } }
  -- use {'cespare/vim-toml', { 'branch': 'main' }}

  -- -- Autocomplete
  -- use 'github/copilot.vim'
  use { 'ms-jpq/coq_nvim', run = 'python3 -m coq deps' }
  use 'ms-jpq/coq.artifacts'
  use 'ms-jpq/coq.thirdparty'

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

  -- LSP
  use 'neovim/nvim-lspconfig'
  use 'dense-analysis/ale'

  use {
    "folke/trouble.nvim",
    requires = { "nvim-tree/nvim-web-devicons" },
  }
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
set synmaxcol=3000
set list
set listchars=tab:·\ ,trail:█
]])

vim.opt.mouse = ""        -- I HATE MICE
vim.opt.gdefault = true   -- Assume the /g flag on :s substitutions to replace all matches in a line
vim.opt.shiftround = true -- When at 3 spaces and I hit >>, go to 4, not 5.
vim.opt.showmode = false  -- Hide -- INSERT -- in cmdline for echodoc

-- Color
vim.opt.termguicolors = true
vim.cmd.colorscheme "catppuccin-mocha" -- catppuccin-latte, catppuccin-frappe, catppuccin-macchiato, catppuccin-mocha

-- syntax enable
vim.cmd.highlight({ "MatchParen", "ctermbg=black" })

vim.g.mapleader = " "

-- Leader Mappings
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

vmap("<Enter>", "<cmd>EasyAlign")

-- more natural movement with wrap on
nmap('j', 'gj')
nmap('k', 'gk')

-- Easy buffer navigation
nmap('<C-h>', '<C-w>h')
nmap('<C-j>', '<C-w>j')
nmap('<C-k>', '<C-w>k')
nmap('<C-l>', '<C-w>l')

nmap("<Right>", "<cmd>bn<CR>")
nmap("<Left>", "<cmd>bp<CR>")

-- Emacs-like beginning and end of line.
imap("<c-e>", "<c-o>$")
imap("<c-a>", "<c-o>^")

-- Because I can't spell
vim.cmd.cabbrev({ "Wq", "wq" })
vim.cmd.cabbrev({ "WQ", "wq" })
vim.cmd.cabbrev({ "Qall", "qall" })
vim.cmd.cabbrev({ "Wqall", "wqall" })

--##############################################################################
--# AUTOCMDS
--##############################################################################

vim.cmd.filetype({ "plugin", "indent", "on" })

vim.cmd([[
augroup indentation
  autocmd!
  autocmd BufReadPost *
        \ if line("'\"") > 0 && line("'\"") <= line("$") |
        \ exe "normal g`\"" |
        \ endif

  " for ruby, autoindent with two spaces, always expand tabs
  autocmd FileType ruby,haml,eruby,yaml,html,javascript set ai sw=2 sts=2 et

  autocmd Filetype markdown setlocal spell
  autocmd FileType swift set ai sw=4 sts=4 et
  autocmd BufNewFile,BufRead Dangerfile set syntax=ruby
augroup END

" Remove trailing whitespace on save
augroup trailingWhitespace
  autocmd BufWritePre * :%s/\s\+$//e
augroup END

augroup gitCommit
  autocmd FileType gitcommit setlocal spell textwidth=72
  autocmd FileType *.md setlocal spell textwidth=80
augroup END
]])

--##############################################################################
--# PLUGIN SETTINGS
--##############################################################################

-- require('nvim-treesitter.configs').setup {
--   ensure_installed = { "lua", "ruby" },
--   sync_install = true,
--   incremental_selection = {
--     enable = true,
--     keymaps = {
--       init_selection = "gnn",
--       node_incremental = "grn",
--       scope_incremental = "grc",
--       node_decremental = "grm",
--     },
--   },
--   textobjects = {
--     select = {
--       enable = true,
--       lookahead = true,
--       keymaps = {
--         ["af"] = "@function.outer",
--         ["if"] = "@function.inner",
--         ["ac"] = "@class.outer",
--         ["ic"] = "@class.inner",
--       },
--     },
--     move = {
--       enable = true,
--       set_jumps = true,
--       goto_next_start = {
--         ["]m"] = "@function.outer",
--         ["]]"] = "@class.outer",
--       },
--       goto_next_end = {
--         ["]M"] = "@function.outer",
--         ["]["] = "@class.outer",
--       },
--       goto_previous_start = {
--         ["[m"] = "@function.outer",
--         ["[["] = "@class.outer",
--       },
--       goto_previous_end = {
--         ["[M"] = "@function.outer",
--         ["[]"] = "@class.outer",
--       },
--     },
--   }
-- }

-- fuzzy finding plugin
local fzf_actions = require 'fzf-lua.actions'

require('fzf-lua').setup({
  'max-perf',
  files = {
    fzf_opts = {
      ['--history'] = vim.fn.stdpath("data") .. '/fzf-lua-files-history',
    },
  },
  actions = {
    files = {
      ["default"] = fzf_actions.file_edit,
      ["ctrl-t"]  = fzf_actions.file_edit,
      ["ctrl-s"]  = fzf_actions.file_split,
      ["ctrl-x"]  = fzf_actions.file_split,
      ["ctrl-v"]  = fzf_actions.file_vsplit,
    },
  }
})
nmap(
  "<Leader>f",
  "<cmd>lua require('fzf-lua').files({ fzf_opts = { ['--layout'] = 'default' } })<CR>"
)
nmap("K", "<cmd>lua require('fzf-lua').grep_cword()<CR>")
nmap(
  "<C-t>",
  "<cmd>lua require('fzf-lua').lsp_definitions()<CR>"
)

-- lualine
require('lualine').setup()

-- -- Mason
-- require("mason").setup()
-- require("mason-lspconfig").setup({
--   ensure_installed = { "lua_ls", "ruby_ls", "tsserver" },
-- })


-- LSP Config
local lsp = require('lspconfig')

local lspFormattingGroup = vim.api.nvim_create_augroup("LspFormatting", {});
vim.api.nvim_create_autocmd(
  { "BufWritePre" },
  {
    pattern = "*",
    callback = function()
      vim.lsp.buf.format()
    end,
    group = lspFormattingGroup,
  }
)

vim.g.coq_settings = {
  auto_start = 'shut-up',
  clients = {
    tabnine = { enabled = true }
  },
  keymap = {
    jump_to_mark = '' -- This defaults to <C-h> which we use to make switching buffers easier
  },
}

local coq = require('coq')
coq.Now()

require("coq_3p") {
  { src = "copilot", short_name = "COP", accept_key = "<c-f>" }
}

lsp.lua_ls.setup(coq.lsp_ensure_capabilities({
  settings = {
    Lua = {
      diagnostics = {
        globals = { "vim" },
      },
    },
  }
}))

lsp.tsserver.setup(coq.lsp_ensure_capabilities())

lsp.ruby_ls.setup(coq.lsp_ensure_capabilities({
  cmd = { "./bin/ruby-lsp" },
  init_options = {
    -- Add Ruby LSP configuration here, eg:
    formatter = "auto"
  },
  enabledfeatures = { "codeactions", "diagnostics", "documenthighlights", "documentsymbols", "formatting", "inlayhint" },
  -- Add your lspconfig configurations/overrides here, eg:
  on_attach = function(client, buffer)
    -- in the case you have an existing `on_attach` function
    -- with mappings you share with other lsp clients configs
    pcall(on_attach, client, buffer)

    local diagnostic_handler = function()
      local params = vim.lsp.util.make_text_document_params(buffer)

      client.request(
        'textDocument/diagnostic',
        { textDocument = params },
        function(err, result)
          if err then
            local err_msg = string.format("./bin/ruby-lsp - diagnostics error - %s", vim.inspect(err))
            vim.lsp.log.error(err_msg)
          end
          if not result then return end

          vim.lsp.diagnostic.on_publish_diagnostics(
            nil,
            vim.tbl_extend('keep', params, { diagnostics = result.items }),
            { client_id = client.id }
          )
        end
      )
    end

    diagnostic_handler() -- to request diagnostics when attaching the client to the buffer

    local ruby_group = vim.api.nvim_create_augroup('ruby_ls', { clear = false })
    vim.api.nvim_create_autocmd(
      { 'BufEnter', 'BufWritePre', 'InsertLeave', 'TextChanged' },
      {
        buffer = buffer,
        callback = diagnostic_handler,
        group = ruby_group,
      }
    )
  end
}))

--COC
-- inoremap <expr> <cr> pumvisible() ? "\<C-y>" : "\<C-g>u\<CR>"
-- inoremap <silent><expr> <cr> coc#pum#visible() ? coc#pum#confirm() : "\<cr>"
-- vim.cmd([[
-- inoremap <expr> <cr> coc#pum#visible() ? coc#_select_confirm() : "\<CR>"
-- ]])

-- nnoremap <nowait><expr> <C-f> coc#float#has_scroll() ? coc#float#scroll(1) : "\<C-f>"
-- nnoremap <nowait><expr> <C-b> coc#float#has_scroll() ? coc#float#scroll(0) : "\<C-b>"
-- inoremap <nowait><expr> <C-f> coc#float#has_scroll() ? "\<c-r>=coc#float#scroll(1)\<cr>" : "\<Right>"
-- inoremap <nowait><expr> <C-b> coc#float#has_scroll() ? "\<c-r>=coc#float#scroll(0)\<cr>" : "\<Left>"

-- nmap("<F2>", "<Plug>(coc-diagnostic-next)")
-- nmap <silent> <leader>A <Plug>(coc-diagnostic-next-error)

-- " Do default action for next item.
-- nnoremap <silent><nowait> <space>j  :<C-u>CocNext<CR>
-- " Do default action for previous item.
-- nnoremap <silent><nowait> <space>k  :<C-u>CocPrev<CR>

--ALE
vim.g.ale_fix_on_save = true
vim.g.ale_linters = {
  eruby = { "erblint" },
  ruby = {},
}
vim.g.ale_fixers = {
  eruby = { "erblint" },
  ruby = {},
}

----ArgWrap
nmap("<Leader>a", "<cmd>ArgWrap<CR>")
vim.g.argwrap_tail_comma = true


----replace 'f' with 1-char Sneak
nmap("f", "<Plug>Sneak_f")
nmap("F", "<Plug>Sneak_F")
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

vim.cmd([[
let g:user_debugger_dictionary = { '\.rb' : 'binding.irb', '\.tsx' : 'debugger' }
]])

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
