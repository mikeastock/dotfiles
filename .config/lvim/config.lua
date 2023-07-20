-- Read the docs: https://www.lunarvim.org/docs/configuration
-- Video Tutorials: https://www.youtube.com/watch?v=sFA9kX-Ud_c&list=PLhoH5vyxr6QqGu0i7tt_XoVK9v-KvZ3m6
-- Forum: https://www.reddit.com/r/lunarvim/
-- Discord: https://discord.com/invite/Xb9B4Ny

-- Don't use fish for performance reasons
vim.opt.shell = "/bin/sh"

-- I HATE MICE
vim.opt.mouse = ""

-- Make vim go to beginning of line
vim.cmd("map 0 ^")

-- Remove search highlight
vim.cmd([[
function! MapCR()
  nnoremap <CR> :nohlsearch<CR>
endfunction
call MapCR()
]])

lvim.colorscheme = "tokyonight-night"

lvim.format_on_save.enabled = true

lvim.builtin.telescope.defaults.path_display = {}

-- Because I can't spell
vim.cmd.cabbrev({ "Wq", "wq" })
vim.cmd.cabbrev({ "WQ", "wq" })
vim.cmd.cabbrev({ "Qall", "qall" })
vim.cmd.cabbrev({ "Wqall", "wqall" })

-- Custom keybindings

-- Handle line wrapping
lvim.keys.normal_mode["j"] = "gj"
lvim.keys.normal_mode["k"] = "gk"

-- Navigate buffers with arrow keys
lvim.keys.normal_mode["<Right>"] = "<cmd>bn<CR>"
lvim.keys.normal_mode["<Left>"] = "<cmd>bp<CR>"

lvim.builtin.which_key.mappings["vi"] = { "<cmd>edit " .. get_config_dir() .. "/config.lua<cr>", "Edit config.lua" }
lvim.builtin.which_key.mappings["q"] = { "<cmd>BufferKill<CR>", "Close Buffer" }

lvim.builtin.which_key.mappings["t"] = { ":TestNearest<CR>", "Test nearest" }
lvim.builtin.which_key.mappings["r"] = { ":TestFile<CR>", "Test file" }

-- lvim.builtin.which_key.mappings["s"] = { "<cmd>lua require('neotest').run.run()<cr>", "Test Method" }
-- lvim.builtin.which_key.mappings["r"] = { "<cmd>lua require('neotest').run.run(vim.fn.expand('%'))<cr>", "Test Method" }
-- lvim.builtin.which_key.mappings["dS"] = { "<cmd>lua require('neotest').summary.toggle()<cr>", "Test Summary" }

-- Configure ruby_ls
vim.list_extend(lvim.lsp.automatic_configuration.skipped_servers, { "solargraph" })
lvim.lsp.automatic_configuration.skipped_servers = vim.tbl_filter(function(server)
  return server ~= "ruby_ls"
end, lvim.lsp.automatic_configuration.skipped_servers)

-- Setup github copilot
table.insert(lvim.plugins, {
  "zbirenbaum/copilot-cmp",
  event = "InsertEnter",
  dependencies = { "zbirenbaum/copilot.lua" },
  config = function()
    vim.defer_fn(function()
      require("copilot").setup()     -- https://github.com/zbirenbaum/copilot.lua/blob/master/README.md#setup-and-configuration
      require("copilot_cmp").setup() -- https://github.com/zbirenbaum/copilot-cmp/blob/master/README.md#configuration
    end, 100)
  end,
})

-- Custom plugins
table.insert(lvim.plugins, {
  "vim-test/vim-test",
  {
    "folke/tokyonight.nvim",
    lazy = false,
    priority = 1000,
    opts = {},
  },

  -- Setup neotest
  -- {
  --   "nvim-neotest/neotest",
  --   dependencies = {
  --     { "nvim-neotest/neotest-vim-test", dependencies = "vim-test/vim-test" },
  --   },
  --   config = function()
  --     require("neotest").setup({
  --       adapters = {
  --         require("neotest-vim-test"),
  --       }
  --     })
  --   end,
  -- }
})
