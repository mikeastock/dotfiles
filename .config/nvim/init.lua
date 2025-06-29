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
vim.opt.mouse = "" -- I HATE MICE
vim.opt.shiftround = true -- When at 3 spaces and I hit >>, go to 4, not 5.
vim.opt.showmode = false -- Hide -- INSERT -- in cmdline for echodoc
vim.opt.splitkeep = "screen" -- Stable splits
vim.g.python3_host_prog = "~/.local/share/mise/shims/python3"

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
nmap("<Leader>yf", "<cmd>let @+=expand('%')<CR>") -- Copy path to clipboard

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

-- Some of tpope's vim-unimpaired mappings
nmap("]q", "<cmd>:cnext<CR>")
nmap("[q", "<cmd>:cprevious<CR>")

vim.cmd([[
let g:user_debugger_dictionary = { '\.rb' : 'binding.pry', '\.tsx' : 'debugger' }
]])

-- Disable default omni completion in sql files
vim.cmd([[
let g:ftplugin_sql_omni_key = '<C-j>'
]])

-- Plugins

-- Bootstrap lazy.nvim
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not (vim.uv or vim.loop).fs_stat(lazypath) then
	local lazyrepo = "https://github.com/folke/lazy.nvim.git"
	local out = vim.fn.system({ "git", "clone", "--filter=blob:none", "--branch=stable", lazyrepo, lazypath })
	if vim.v.shell_error ~= 0 then
		vim.api.nvim_echo({
			{ "Failed to clone lazy.nvim:\n", "ErrorMsg" },
			{ out, "WarningMsg" },
			{ "\nPress any key to exit..." },
		}, true, {})
		vim.fn.getchar()
		os.exit(1)
	end
end
vim.opt.rtp:prepend(lazypath)

require("lazy").setup({
	spec = {
		-- fuzzy finding
		-- {
		--   "nvim-telescope/telescope.nvim",
		--   tag = "0.1.6",
		--   dependencies = { "nvim-lua/plenary.nvim" },
		--   config = function()
		--     require("telescope").setup({
		--       defaults = {
		--         layout_config = {
		--           prompt_position = "top",
		--         },
		--         mappings = {
		--           i = {
		--             ["<C-j>"] = require("telescope.actions").move_selection_next,
		--             ["<C-k>"] = require("telescope.actions").move_selection_previous,
		--           },
		--         },
		--       },
		--     })

		--     local builtin = require('telescope.builtin')
		--     vim.keymap.set('n', '<leader>f', builtin.find_files, {})
		--     vim.keymap.set('n', 'K', builtin.grep_string, {})
		--   end,
		-- },
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
			end,
		},

		-- UI

		-- workflow
		{
			"FooSoft/vim-argwrap",
			config = function()
				nmap("<Leader>a", "<cmd>ArgWrap<CR>")
				vim.g.argwrap_tail_comma = true
			end,
		},

		-- {
		--   "lewis6991/gitsigns.nvim",
		--   event = "VeryLazy",
		--   opts = {},
		-- },

		"junegunn/vim-easy-align",
		{
			"justinmk/vim-sneak",
			config = function()
				nmap("f", "<Plug>Sneak_f")
				nmap("F", "<Plug>Sneak_F")
			end,
		},
		"mikeastock/vim-infer-debugger",
		"pbrisbin/vim-mkdir",
		{
			"tpope/vim-abolish",
			setup = function()
				vim.cmd([[
        ]])
			end,
		},
		-- "tpope/vim-commentary",
		"tpope/vim-dispatch",
		"tpope/vim-fugitive",
		"tpope/vim-surround",

		{
			"andymass/vim-matchup",
			setup = function()
				-- may set any options here
				vim.g.matchup_matchparen_offscreen = { method = "popup" }
			end,
		},

		-- testing
		{
			"vim-test/vim-test",
			init = function()
				vim.g["test#strategy"] = {
					nearest = "basic",
					file = "basic",
					suite = "dispatch",
				}
				-- vim.g["test#neovim#term_position"] = "botright"

				-- vim.keymap.set('n', '<Leader>s', function() require('neotest').run.run() end)
				-- nmap("<Leader>s", "<cmd>lua require('neotest').run.run()<CR>")
				nmap("<Leader>s", ":TestNearest<CR>")
				-- vim.keymap.set('n', '<Leader>r', function() require('neotest').run.run(vim.fn.expand('%')) end)
				-- nmap("<Leader>r", "<cmd>lua require('neotest').run.run(vim.fn.expand('%'))<CR>")
				nmap("<Leader>r", ":TestFile<CR>")

				-- Make escape work in the Neovim terminal.
				tmap("<Esc>", "<C-\\><C-n>")
			end,
		},
		-- "kassio/neoterm",
		-- {
		--   "nvim-neotest/neotest",
		--   dependencies = {
		--     "nvim-lua/plenary.nvim",
		--     "antoinemadec/FixCursorHold.nvim",
		--     "nvim-treesitter/nvim-treesitter",
		--     "mikeastock/neotest-minitest",
		--   },
		--   config = function()
		--     require("neotest").setup({
		--       default_strategy = "integrated",
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

		-- colors/themes
		{
			"lmantw/themify.nvim",
			lazy = false,
			priority = 999,
			config = function()
				require("themify").setup({
					"catppuccin/nvim",
					"folke/tokyonight.nvim",
					"ellisonleao/gruvbox.nvim",
					"sainnhe/everforest",
					"shaunsingh/nord.nvim",
					"EdenEast/nightfox.nvim",
					"neanias/everforest-nvim",
					"rebelot/kanagawa.nvim",
					"nyoom-engineering/oxocarbon.nvim",
					"jacoborus/tender.vim",
					"scottmckendry/cyberdream.nvim",
					"olimorris/onedarkpro.nvim",
					"zenbones-theme/zenbones.nvim",
				})
			end,
			dependencies = {
				"rktjmp/lush.nvim", -- Used by zenbones theme
			},
		},
		-- {
		--   "catppuccin/nvim",
		--   name = "catppuccin",
		--   priority = 1000
		-- },
		-- {
		--   "folke/tokyonight.nvim",
		--   lazy = true,
		--   opts = { style = "moon" },
		-- },

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
		-- AI
		-- {
		--   "ggml-org/llama.vim",
		-- },
		{
			"supermaven-inc/supermaven-nvim",
			config = function()
				require("supermaven-nvim").setup({
					keymaps = {
						accept_suggestion = "<C-f>",
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
			end,
		},

		-- Formatting
		{
			"stevearc/conform.nvim",
			config = function()
				require("conform").setup({
					formatters_by_ft = {
						lua = { "stylua" },
						-- Conform will run multiple formatters sequentially
						python = { "isort", "black" },
						-- You can customize some of the format options for the filetype (:help conform.format)
						rust = { "rustfmt", lsp_format = "fallback" },
						-- Conform will run the first available formatter
						javascript = { "prettierd", "prettier", stop_after_first = true },
					},
					format_on_save = {
						-- These options will be passed to conform.format()
						timeout_ms = 500,
						lsp_format = "fallback",
					},
				})
			end,
		},

		-- Langauge specific

		-- JS
		-- { "HerringtonDarkholme/yats.vim",           ft = "typescript" },
		-- { "othree/javascript-libraries-syntax.vim", ft = "javascript" },
		-- { "pangloss/vim-javascript",                ft = "javascript" },

		-- Ruby
		-- { "Keithbsmiley/rspec.vim", ft = "ruby" },
		{
			"tpope/vim-rails",
			ft = "ruby",
			config = function()
				-- disable autocmd set filetype=eruby.yaml
				vim.api.nvim_create_autocmd("FileType", {
					pattern = "eruby.yaml",
					command = "set filetype=yaml",
				})
			end,
		},
		-- { "vim-ruby/vim-ruby",                      ft = "ruby" },

		-- Elixir
		-- { "elixir-lang/vim-elixir", ft = "elixir,eelixir" },
		-- { "mhinz/vim-mix-format",   ft = "elixir,eelixir" },

		-- Misc
		-- { "amadeus/vim-mjml",       ft = "mjml" },
		-- { "andys8/vim-elm-syntax",  ft = "elm" },
		-- { "dag/vim-fish",           ft = "fish" },
		-- { "fatih/vim-go",           ft = "golang" },
		-- { "hashivim/vim-terraform", ft = "terraform" },
		-- { "jvirtanen/vim-hcl",                      ft = "hcl" },
		-- { "rust-lang/rust.vim",     ft = "rust" },
	},
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

-- Configure Tabline
-- Function to create a bufferline that only shows full paths for duplicated filenames
function _G.MyBufferline()
	local s = ""
	local current = vim.fn.bufnr("%")
	local buffers = vim.fn.getbufinfo({ buflisted = 1 })

	-- First, collect all filenames to check for duplicates
	local filename_counts = {}
	local duplicate_files = {}

	-- Count occurrences of each filename
	for _, buf in ipairs(buffers) do
		local name = buf.name ~= "" and vim.fn.fnamemodify(buf.name, ":t") or "[No Name]"
		filename_counts[name] = (filename_counts[name] or 0) + 1

		-- If we've seen this name more than once, mark it as a duplicate
		if filename_counts[name] > 1 then
			duplicate_files[name] = true
		end
	end

	-- Now build the bufferline
	for _, buf in ipairs(buffers) do
		-- Select the highlighting
		if buf.bufnr == current then
			s = s .. "%#TabLineSel#"
		else
			s = s .. "%#TabLine#"
		end

		-- Get the buffer name
		local name
		if buf.name ~= "" then
			local basename = vim.fn.fnamemodify(buf.name, ":t")

			-- Show full path only for files with duplicate names
			if duplicate_files[basename] then
				name = vim.fn.fnamemodify(buf.name, ":~:.")
			else
				name = basename
			end
		else
			name = "[No Name]"
		end

		s = s .. " " .. name

		-- Add modified indicator
		if buf.changed == 1 then
			s = s .. " [+]"
		end

		s = s .. " "
	end

	-- Fill the rest of the tabline
	s = s .. "%#TabLineFill#"

	return s
end

-- Set the tabline to use our custom function
vim.opt.showtabline = 2 -- Always show tabline
vim.opt.tabline = "%!v:lua.MyBufferline()"

-- LAST
-- vim.cmd.colorscheme "tokyonight-night"
-- vim.cmd.colorscheme "tokyonight-day"
-- vim.cmd.colorscheme "catppuccin-latte"
