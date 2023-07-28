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

vim.opt.mouse = ""        -- I HATE MICE
vim.opt.gdefault = true   -- Assume the /g flag on :s substitutions to replace all matches in a line
vim.opt.shiftround = true -- When at 3 spaces and I hit >>, go to 4, not 5.
vim.opt.showmode = false  -- Hide -- INSERT -- in cmdline for echodoc

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
  "ibhagwan/fzf-lua",

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
    event = "VeryLazy",
    opts = {},
  },

  {
    "andymass/vim-matchup",
    setup = function()
      -- may set any options here
      vim.g.matchup_matchparen_offscreen = { method = "popup" }
    end
  },

  -- Autocomplete
  -- {
  --   "github/copilot.vim",
  --   event = "InsertEnter",
  -- },
  {
    "zbirenbaum/copilot.lua",
    cmd = "Copilot",
    event = "InsertEnter",
    config = function()
      require("copilot").setup({
        -- suggestion = { enabled = false },
        -- panel = { enabled = false },
        suggestion = {
          auto_trigger = true,
          keymap = {
            accept = "<C-f>",
          },
        },
      })
    end,
  },
  -- snippets
  {
    "L3MON4D3/LuaSnip",
    dependencies = {
      "rafamadriz/friendly-snippets",
      config = function()
        require("luasnip.loaders.from_vscode").lazy_load()
      end,
    },
    opts = {
      history = true,
      delete_check_events = "TextChanged",
    },
    -- stylua: ignore
    keys = {
      {
        "<tab>",
        function()
          return require("luasnip").jumpable(1) and "<Plug>luasnip-jump-next" or "<tab>"
        end,
        expr = true,
        silent = true,
        mode = "i",
      },
      { "<tab>",   function() require("luasnip").jump(1) end,  mode = "s" },
      { "<s-tab>", function() require("luasnip").jump(-1) end, mode = { "i", "s" } },
    },
  },
  {
    "hrsh7th/nvim-cmp",
    version = false, -- last release is way too old
    event = "InsertEnter",
    dependencies = {
      "hrsh7th/cmp-nvim-lsp",
      "hrsh7th/cmp-buffer",
      "hrsh7th/cmp-path",
      "saadparwaiz1/cmp_luasnip",
      { "roobert/tailwindcss-colorizer-cmp.nvim", opts = {} },
      -- {
      --   "zbirenbaum/copilot-cmp",
      --   config = function()
      --     require("copilot_cmp").setup()
      --   end
      -- }
    },
    opts = function(_, _)
      local cmp = require("cmp")
      local defaults = require("cmp.config.default")()

      -- cmp.event:on("menu_opened", function()
      --   vim.b.copilot_suggestion_hidden = true
      -- end)

      -- cmp.event:on("menu_closed", function()
      --   vim.b.copilot_suggestion_hidden = false
      -- end)

      return {
        completion = {
          completeopt = "menu,menuone,noinsert",
        },
        snippet = {
          expand = function(args)
            require("luasnip").lsp_expand(args.body)
          end,
        },
        mapping = cmp.mapping.preset.insert({
          ["<C-n>"] = cmp.mapping.select_next_item({ behavior = cmp.SelectBehavior.Insert }),
          ["<C-p>"] = cmp.mapping.select_prev_item({ behavior = cmp.SelectBehavior.Insert }),
          ["<C-b>"] = cmp.mapping.scroll_docs(-4),
          ["<C-f>"] = cmp.mapping.scroll_docs(4),
          ["<C-Space>"] = cmp.mapping.complete(),
          ["<C-e>"] = cmp.mapping.abort(),
          ["<CR>"] = cmp.mapping.confirm({ select = true }), -- Accept currently selected item. Set `select` to `false` to only confirm explicitly selected items.
          ["<S-CR>"] = cmp.mapping.confirm({
            behavior = cmp.ConfirmBehavior.Replace,
            select = true,
          }),                                                      -- Accept currently selected item. Set `select` to `false` to only confirm explicitly selected items.
          ["<C-f>"] = require("copilot.suggestion").accept_line(), -- Allow accepting copilot with cmp open
        }),
        sources = cmp.config.sources({
          { name = "nvim_lsp" },
          { name = "luasnip" },
          { name = "buffer" },
          { name = "path" },
        }),
        sorting = defaults.sorting,
      }
    end
  },

  -- testing
  "vim-test/vim-test",
  "kassio/neoterm",

  -- colors
  "catppuccin/nvim",
  {
    "folke/tokyonight.nvim",
    lazy = true,
    opts = { style = "moon" },
  },

  -- LSP
  {
    "neovim/nvim-lspconfig",
    event = { "BufReadPre", "BufNewFile" },
    dependencies = {
      { "folke/neodev.nvim", opts = {} },
      "hrsh7th/cmp-nvim-lsp",
      "jose-elias-alvarez/typescript.nvim",
    },
    opts = {
      -- add any global capabilities here
      capabilities = {},

      -- LSP Server Settings
      ---@type lspconfig.options
      servers = {
        lua_ls = {
          settings = {
            Lua = {
              completion = {
                callSnippet = "Replace"
              },
              diagnostics = {
                globals = { "vim" },
              },
            },
          }
        },
        ruby_ls = {},
        tailwindcss = {
          filetypes_exclude = { "markdown" },
        },
        tsserver = {},
      },
      setup = {
        ruby_ls = function(_, opts)
          _timers = {}

          local function setup_diagnostics(client, buffer)
            if require("vim.lsp.diagnostic")._enable then
              return
            end

            local diagnostic_handler = function()
              local params = vim.lsp.util.make_text_document_params(buffer)
              client.request("textDocument/diagnostic", { textDocument = params }, function(err, result)
                if err then
                  local err_msg = string.format("diagnostics error - %s", vim.inspect(err))
                  vim.lsp.log.error(err_msg)
                end
                if not result then
                  return
                end
                vim.lsp.diagnostic.on_publish_diagnostics(
                  nil,
                  vim.tbl_extend("keep", params, { diagnostics = result.items }),
                  { client_id = client.id }
                )
              end)
            end

            diagnostic_handler() -- to request diagnostics on buffer when first attaching

            vim.api.nvim_buf_attach(buffer, false, {
              on_lines = function()
                if _timers[buffer] then
                  vim.fn.timer_stop(_timers[buffer])
                end
                _timers[buffer] = vim.fn.timer_start(200, diagnostic_handler)
              end,
              on_detach = function()
                if _timers[buffer] then
                  vim.fn.timer_stop(_timers[buffer])
                end
              end,
            })
          end

          require("lspconfig").ruby_ls.setup({
            on_attach = function(client, buffer)
              setup_diagnostics(client, buffer)
            end,
          })

          return true
        end,
        tailwindcss = function(_, opts)
          local tw = require("lspconfig.server_configurations.tailwindcss")
          --- @param ft string
          opts.filetypes = vim.tbl_filter(function(ft)
            return not vim.tbl_contains(opts.filetypes_exclude or {}, ft)
          end, tw.default_config.filetypes)
        end,
        tsserver = function(_, opts)
          require("typescript").setup({ server = opts })
          return true
        end,
      },
    },
    config = function(_, opts)
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

      local servers = opts.servers
      local cmp_nvim_lsp = require("cmp_nvim_lsp")
      local capabilities = vim.tbl_deep_extend(
        "force",
        {},
        vim.lsp.protocol.make_client_capabilities(),
        cmp_nvim_lsp.default_capabilities(),
        opts.capabilities
      )

      local function setup(server)
        local server_opts = vim.tbl_deep_extend(
          "force",
          { capabilities = vim.deepcopy(capabilities) },
          servers[server] or {}
        )

        if opts.setup[server] then
          if opts.setup[server](server, server_opts) then
            return
          end
        end

        require("lspconfig")[server].setup(server_opts)
      end

      for server, _ in pairs(servers) do
        setup(server)
      end
    end,
    lazy = false,
  },
  "dense-analysis/ale",

  {
    "folke/trouble.nvim",
    dependencies = { "nvim-tree/nvim-web-devicons" },
  },

  -- Langauge specific

  -- JS
  { "HerringtonDarkholme/yats.vim",           ft = "typescript" },
  { "othree/javascript-libraries-syntax.vim", ft = "javascript" },
  { "pangloss/vim-javascript",                ft = "javascript" },

  -- Ruby
  { "Keithbsmiley/rspec.vim",                 ft = "ruby" },
  { "tpope/vim-rails",                        ft = "ruby" },
  { "vim-ruby/vim-ruby",                      ft = "ruby" },

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

-- fuzzy finding plugin
local fzf_actions = require "fzf-lua.actions"

require("fzf-lua").setup({
  "max-perf",
  files = {
    fzf_opts = {
      ["--history"] = vim.fn.stdpath("data") .. "/fzf-lua-files-history",
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


----replace "f" with 1-char Sneak
nmap("f", "<Plug>Sneak_f")
nmap("F", "<Plug>Sneak_F")

-- Testing settings
nmap("<Leader>s", ":TestNearest<CR>")
nmap("<Leader>t", ":TestNearest<CR>")
nmap("<Leader>T", ":TestFile<CR>")
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
