# Publishing the LocalVault website

The public website lives at [localvault.kuickr.co](https://localvault.kuickr.co/).
GitHub Pages serves a forwarding home page and the repository's original
`install.sh`, following the Baari distribution pattern.

`landing.html` is the single authored site source. `nodepad-tokens.css` is a
pinned snapshot of Kuickr's registered Nodepad design system, version
`72656b12-a210-4c77-b915-b26e3bc49b47`. Build the self-contained deployment:

```sh
python3 tools/build-site.py
```

Publish `.kuickr-build/index.html` to the existing
`localvault/guide/index.html` Page with Kuickr MCP or:

```sh
kuickr add .kuickr-build/index.html localvault/guide --as index.html
```

The generated directory is ignored by Git. Edit the source, rebuild, and
republish; do not edit the hosted projection. Only explicitly selected Pages
in the public guide belong on the named address. Internal plans, sessions,
agent coordination, and backlog remain private in their existing folders.

The demo is a non-executing fixture replay. It accepts no credentials and
does not connect to vaults. Keep claims about proposed user-owned storage
distinct from the currently shipped InventList sync behavior.

The repository's `index.html` forwards visitors to Kuickr. Configure GitHub
Pages to serve `main` at `/`; `.nojekyll` keeps the distribution files static.
The stable installer address is:

```text
https://inventlist.github.io/localvault/install.sh
```

Moving the website does not migrate vault data, accounts, or the sync server.
