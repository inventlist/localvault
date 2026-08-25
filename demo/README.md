# Demo assets

`localvault.tape` records the CLI demo GIF with [vhs](https://github.com/charmbracelet/vhs):

```bash
brew install vhs
vhs demo/localvault.tape     # writes localvault-demo.gif
```

The tape runs against a throwaway `LOCALVAULT_HOME` (`mktemp -d`), so it never
touches real vaults. Static stills of help output are made with
[freeze](https://github.com/charmbracelet/freeze):

```bash
freeze -x "localvault help groups" -o help.png --window --theme charm --font.family Menlo
```

Note: freeze's `-W` is pixels, and without `--font.family` it falls back to a
proportional font that breaks column alignment.
