#!/bin/sh
# localvault installer — installs the gem into an isolated prefix and puts a
# self-contained wrapper on your PATH. Never touches your project gems, never
# creates a version-manager shim.
#
#   curl -sSL https://raw.githubusercontent.com/inventlist/localvault/main/install.sh | sh
#
# Options (env vars):
#   LOCALVAULT_BIN_DIR   install dir (default: /usr/local/bin if writable, else ~/.local/bin)
#   LOCALVAULT_PREFIX    gem prefix   (default: ~/.localvault/runtime)
#   LOCALVAULT_VERSION   pin a version, e.g. 1.9.0 (default: latest)
#   LOCALVAULT_RUBY      ruby to run localvault with (default: auto-detected)
#
# macOS/Linuxbrew users can instead: brew install inventlist/tap/localvault
set -eu

GEM_NAME="localvault"
BINARY="localvault"
VERSION="${LOCALVAULT_VERSION:-latest}"
PREFIX="${LOCALVAULT_PREFIX:-$HOME/.localvault/runtime}"

err()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$1" >&2; }

# ── Pick a ruby ───────────────────────────────────────────────────
# Prefer a stable, non-version-manager ruby: a wrapper pinned to an asdf/rbenv
# shim breaks the moment you switch versions in a project.
pick_ruby() {
  if [ -n "${LOCALVAULT_RUBY:-}" ]; then echo "$LOCALVAULT_RUBY"; return; fi
  for candidate in \
    /opt/homebrew/opt/ruby/bin/ruby \
    /usr/local/opt/ruby/bin/ruby \
    /usr/bin/ruby
  do
    [ -x "$candidate" ] && { echo "$candidate"; return; }
  done
  # Fall back to PATH ruby, resolving shims to the real binary where possible.
  command -v ruby >/dev/null 2>&1 || err "no ruby found — install ruby >= 3.2 (macOS: brew install ruby)"
  command -v ruby
}

RUBY="$(pick_ruby)"
[ -x "$RUBY" ] || err "ruby not executable: $RUBY"

case "$RUBY" in
  *"/.asdf/"*|*"/.rbenv/"*|*"/.rvm/"*)
    warn "using a version-manager ruby ($RUBY); it may disappear when you switch versions."
    warn "set LOCALVAULT_RUBY=/path/to/stable/ruby, or: brew install ruby" ;;
esac

RUBY_OK=$("$RUBY" -e 'print(Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.2.0") ? "yes" : "no")' 2>/dev/null || echo no)
[ "$RUBY_OK" = "yes" ] || err "$RUBY is $("$RUBY" -e 'print RUBY_VERSION' 2>/dev/null || echo unknown); localvault needs >= 3.2.0"

GEM="$(dirname "$RUBY")/gem"
[ -x "$GEM" ] || GEM="$(command -v gem)" || err "no gem command alongside $RUBY"

# ── libsodium (RbNaCl needs the shared library) ───────────────────
if ! { [ -f /opt/homebrew/lib/libsodium.dylib ] || [ -f /usr/local/lib/libsodium.dylib ] || \
       [ -f /usr/lib/libsodium.so ] || [ -f /usr/lib64/libsodium.so ] || \
       ls /usr/lib/*/libsodium.so* >/dev/null 2>&1; }; then
  warn "libsodium not found — install it or localvault cannot encrypt:"
  warn "  macOS: brew install libsodium    Debian/Ubuntu: apt install libsodium23"
fi

# ── Pick an install dir ───────────────────────────────────────────
if [ -n "${LOCALVAULT_BIN_DIR:-}" ]; then
  BIN_DIR="$LOCALVAULT_BIN_DIR"
elif [ -w /usr/local/bin ] 2>/dev/null; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="$HOME/.local/bin"
fi
mkdir -p "$BIN_DIR" || err "cannot create $BIN_DIR"

# ── Install the gem into an isolated prefix ───────────────────────
info "installing $GEM_NAME into $PREFIX (ruby: $RUBY)"
mkdir -p "$PREFIX"
if [ "$VERSION" = "latest" ]; then
  GEM_HOME="$PREFIX" GEM_PATH="$PREFIX" "$GEM" install "$GEM_NAME" \
    --no-document --install-dir "$PREFIX" >/dev/null || err "gem install failed"
else
  GEM_HOME="$PREFIX" GEM_PATH="$PREFIX" "$GEM" install "$GEM_NAME" -v "$VERSION" \
    --no-document --install-dir "$PREFIX" >/dev/null || err "gem install failed"
fi

# ── Write the wrapper ─────────────────────────────────────────────
# The wrapper pins GEM_HOME and the ruby, so localvault never depends on the
# ruby that happens to be active in your shell.
cat > "$BIN_DIR/$BINARY" <<WRAPPER
#!/bin/sh
export GEM_HOME="$PREFIX"
export GEM_PATH="$PREFIX"
exec "$RUBY" "$PREFIX/bin/$BINARY" "\$@"
WRAPPER
chmod +x "$BIN_DIR/$BINARY"

INSTALLED="$("$BIN_DIR/$BINARY" version 2>/dev/null || echo "")"
[ -n "$INSTALLED" ] || err "installed, but $BIN_DIR/$BINARY did not run — check ruby and libsodium"
info "installed $INSTALLED → $BIN_DIR/$BINARY"

# ── PATH and shadowing checks ─────────────────────────────────────
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add it:"
     warn "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc" ;;
esac

FIRST="$(command -v "$BINARY" 2>/dev/null || true)"
if [ -n "$FIRST" ] && [ "$FIRST" != "$BIN_DIR/$BINARY" ]; then
  warn "another $BINARY is earlier on your PATH: $FIRST"
  warn "run '$BIN_DIR/$BINARY doctor' to see every copy, and remove the stale one"
  warn "(a 'gem install localvault' under asdf/rbenv is the usual culprit)"
fi

printf '\n'
info "next: $BINARY init      # create your vault"
info "      $BINARY guard install   # block secrets in AI agent commands"
