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
  map("n", shortcut, command)
end

function imap(shortcut, command)
  map("i", shortcut, command)
end

function vmap(shortcut, command)
  map("v", shortcut, command)
end

function cmap(shortcut, command)
  map("c", shortcut, command)
end

function tmap(shortcut, command)
  map("t", shortcut, command)
end

-- Global options

vim.g.mapleader = " "

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

vim.opt.gdefault = true -- Assume the /g flag on :s substitutions to replace all matches in a line
vim.opt.grepformat = "%f:%l:%c:%m"
vim.opt.grepprg = "rg --vimgrep"
vim.opt.mouse = ""           -- I HATE MICE
vim.opt.shiftround = true    -- When at 3 spaces and I hit >>, go to 4, not 5.
vim.opt.showmode = false     -- Hide -- INSERT -- in cmdline for echodoc
vim.opt.splitkeep = "screen" -- Stable splits

-- Color
vim.opt.termguicolors = true

-- syntax enable
vim.cmd.highlight({ "MatchParen", "ctermbg=black" })

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

vmap("<Enter>", "<cmd>EasyAlign<CR>")

-- more natural movement with wrap on
nmap("j", "gj")
nmap("k", "gk")

-- Easy buffer navigation
nmap("<C-h>", "<C-w>h")
nmap("<C-j>", "<C-w>j")
nmap("<C-k>", "<C-w>k")
nmap("<C-l>", "<C-w>l")

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

vim.cmd([[
let g:user_debugger_dictionary = { '\.rb' : 'binding.irb', '\.tsx' : 'debugger' }
]])

-- Plugins

local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git",
    "clone",
    "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable", -- latest stable release
    lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

require("lazy").setup({
  -- fuzzy finding
  {
    "junegunn/fzf.vim",
    run = ":call fzf#install()",
    dependencies = { "junegunn/fzf" },
    config = function()
      vim.cmd([[
        let $FZF_DEFAULT_COMMAND = 'rg --hidden --glob "!**/.git/**" --files'

        " Empty value to disable preview window altogether
        let g:fzf_preview_window = []

        " Enable per-command history.
        " CTRL-N and CTRL-P will be automatically bound to next-history and
        " previous-history instead of down and up. If you don't like the change,
        " explicitly bind the keys to down and up in your $FZF_DEFAULT_OPTS.
        let g:fzf_history_dir = '~/.local/share/fzf-history'
      ]])

      nmap("<Leader>f", ":Files<CR>")
      nmap("K", ":Rg <C-R><C-W><CR>")
    end
  },

  -- UI
  {
    "nvim-lualine/lualine.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
    event = "VeryLazy",
    opts = {},
  },

  -- workflow
  "FooSoft/vim-argwrap",
  {
    "lewis6991/gitsigns.nvim",
    event = "VeryLazy",
    opts = {},
  },

  "ap/vim-buftabline",
  "junegunn/vim-easy-align",
  "justinmk/vim-sneak",
  "mikeastock/vim-infer-debugger",
  "pbrisbin/vim-mkdir",
  "tpope/vim-abolish",
  "tpope/vim-commentary",
  "tpope/vim-dispatch",
  "tpope/vim-fugitive",
  "tpope/vim-surround",

  -- CSS Color Previews
  {
    "norcalli/nvim-colorizer.lua",
    event = "BufReadPre",
    opts = {},
  },

  {
    "andymass/vim-matchup",
    setup = function()
      -- may set any options here
      vim.g.matchup_matchparen_offscreen = { method = "popup" }
    end,
  },

  -- testing
  "vim-test/vim-test",
  "kassio/neoterm",
  -- {
  --   "nvim-neotest/neotest",
  --   dependencies = {
  --     "nvim-lua/plenary.nvim",
  --     "zidhuss/neotest-minitest",
  --   },
  --   config = function()
  --     require("neotest").setup({
  --       adapters = {
  --         require("neotest-minitest")({
  --           test_cmd = function()
  --             return vim.tbl_flatten({
  --               "bundle",
  --               "exec",
  --               "rails",
  --               "test",
  --             })
  --           end,
  --         }),
  --       },
  --     })
  --   end,
  -- },

  -- colors
  "catppuccin/nvim",
  {
    "folke/tokyonight.nvim",
    lazy = true,
    opts = { style = "moon" },
  },

  -- COC
  {
    "neoclide/coc.nvim",
    branch = "release",
    event = "VeryLazy",
    config = function()
      vim.cmd([[
      "COC
      inoremap <expr> <cr> coc#pum#visible() ? coc#_select_confirm() : "\<CR>"

      nmap <silent> gr <Plug>(coc-references)
      nmap <silent> <F3> <Plug>(coc-rename)

      " Find symbol of current document.
      nnoremap <silent><nowait> <space>o  :<C-u>CocList outline<cr>

      nmap <silent> <F2> <Plug>(coc-diagnostic-next)

      let g:coc_filetype_map = {
        \ 'rspec.ruby': 'ruby',
        \ }
      ]])
    end,
  },
  {
    "zbirenbaum/copilot.lua",
    config = function()
      require("copilot").setup({
        panel = {
          enabled = false,
          auto_refresh = true,
        },
        suggestion = {
          auto_trigger = true,
          keymap = {
            accept = "<C-f>",
            next = "<C-[>",
            prev = "<C-]>",
          },
        },
      })
    end,
  },

  -- Tree sitter
  {
    "nvim-treesitter/nvim-treesitter",
    run = ":TSUpdate",
    event = "BufRead",
    config = function()
      local configs = require("nvim-treesitter.configs")

      configs.setup({
        ensure_installed = {
          "lua",
          "javascript",
          "html",
          "css",
          "typescript",
          "tsx",
          "ruby",
        },
        sync_install = false,
        highlight = { enable = true },
        indent = { enable = true },
      })
    end
  },

  -- Langauge specific

  -- JS
  { "HerringtonDarkholme/yats.vim",           ft = "typescript" },
  { "othree/javascript-libraries-syntax.vim", ft = "javascript" },
  { "pangloss/vim-javascript",                ft = "javascript" },

  -- Ruby
  { "Keithbsmiley/rspec.vim",                 ft = "ruby" },
  { "tpope/vim-rails",                        ft = "ruby" },
  -- { "vim-ruby/vim-ruby",                      ft = "ruby" },

  -- Elixir
  { "elixir-lang/vim-elixir",                 ft = "elixir,eelixir" },
  { "mhinz/vim-mix-format",                   ft = "elixir,eelixir" },

  -- Misc
  { "amadeus/vim-mjml",                       ft = "mjml" },
  { "andys8/vim-elm-syntax",                  ft = "elm" },
  { "dag/vim-fish",                           ft = "fish" },
  { "fatih/vim-go",                           ft = "golang" },
  { "hashivim/vim-terraform",                 ft = "terraform" },
  { "jvirtanen/vim-hcl",                      ft = "hcl" },
  { "rust-lang/rust.vim",                     ft = "rust" },
})

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

----ArgWrap
nmap("<Leader>a", "<cmd>ArgWrap<CR>")
vim.g.argwrap_tail_comma = true

----replace "f" with 1-char Sneak
nmap("f", "<Plug>Sneak_f")
nmap("F", "<Plug>Sneak_F")

-- Testing settings
-- nmap("<Leader>s", "<cmd>lua require('neotest').run.run()<CR>")
nmap("<Leader>s", ":TestNearest<CR>")
-- nmap("<Leader>r", "<cmd>lua require('neotest').run.run(vim.fn.expand('%'))<CR>")
nmap("<Leader>r", ":TestFile<CR>")

-- Make escape work in the Neovim terminal.
tmap("<Esc>", "<C-\\><C-n>")

-- I like relative numbering when in normal mode.
vim.cmd("autocmd TermOpen * setlocal conceallevel=0 colorcolumn=0 relativenumber")

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

-- LAST
vim.cmd([[colorscheme tokyonight-night]])
