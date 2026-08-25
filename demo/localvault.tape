# LocalVault demo — render with: vhs localvault.tape
Output localvault-demo.gif

Set Shell "bash"
Set FontSize 22
Set FontFamily "Menlo"
Set Width 1280
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Throwaway vault dir — nothing here touches real secrets
Hide
Type "export LOCALVAULT_HOME=$(mktemp -d) PS1='$ '" Enter
Type "clear" Enter
Show

Sleep 600ms
Type "localvault init kuickr-demo" Enter
Sleep 600ms
Type "demo-passphrase" Enter
Sleep 300ms
Type "demo-passphrase" Enter
Sleep 1.5s

Hide
Type "localvault switch kuickr-demo >/dev/null" Enter
Type "localvault unlock >/dev/null" Enter
Type "demo-passphrase" Enter
Sleep 500ms
Type "clear" Enter
Show

# Store secrets the safe way — the value never touches argv or shell history
Type "printf '%s' 'sk_live_4eC39HqLyjWDarjt' | localvault set kuickr.STRIPE_KEY --stdin" Enter
Sleep 1.4s
Type "printf '%s' 'postgres://localhost/kuickr' | localvault set kuickr.DATABASE_URL --stdin" Enter
Sleep 1.4s
Type "printf '%s' 'shppa_9f2b71c4d8e3' | localvault set inventlist.SHOPIFY_TOKEN --stdin" Enter
Sleep 1.8s

# Projects = dot-notation groups inside one vault
Type "localvault groups" Enter
Sleep 2.8s

Type "localvault show -p kuickr" Enter
Sleep 3.2s

# Inject one project into a process — no .env file, nothing on disk
Type "localvault exec -p kuickr -- sh -c 'echo STRIPE_KEY=${#STRIPE_KEY} chars, never written to disk'" Enter
Sleep 3.5s

Hide
Type "clear" Enter
Show
Type "localvault help groups" Enter
Sleep 4.5s
