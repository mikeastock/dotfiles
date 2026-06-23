# Amp plugins

This directory is the source of truth for personal Amp plugins managed by this dotfiles repo.

Put plugin files here as `*.ts`. `make install-amp-plugins` copies them into `~/.config/amp/plugins/`. Because plugins are copied rather than symlinked, rerun the install command after each edit before reloading Amp.

## Included plugins

- `thread-workers.ts` — adds `spawn_worker` for starting builtin Amp agents in worker threads, and `send_to_thread` for reporting results or feedback between threads.

## Development loop

1. Refresh the local plugin API declarations:
   ```bash
   make amp-plugin-types
   ```
2. Create or edit a plugin, for example `amp-plugins/my-plugin.ts`:
   ```ts
   import type { PluginAPI } from '@ampcode/plugin'

   export default function (amp: PluginAPI) {
     amp.logger.log('my-plugin loaded')
   }
   ```
3. Typecheck plugins:
   ```bash
   make amp-plugin-check
   ```
4. Install plugins:
   ```bash
   make install-amp-plugins
   ```
5. In Amp, run `plugins: reload` from the command palette, or restart Amp.

Useful commands:

```bash
amp plugins show-docs
amp plugins list
amp plugins exec ~/.config/amp/plugins/my-plugin.ts session.start --data '{"thread":{"id":"T-test"}}'
```
