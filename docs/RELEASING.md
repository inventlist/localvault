# Releasing localvault

Every shippable code change gets a full release — gem, Homebrew tap, and an
announcement tweet. Don't stop at committing.

## 1. Bump the version

- `lib/localvault/version.rb` — `VERSION = "x.y.z"`
- `Gemfile.lock` — the `localvault (x.y.z)` line under `PATH`

## 2. Verify locally

```bash
bundle exec rake test          # must be green
gem build localvault.gemspec   # must build cleanly
```

## 3. Commit, tag, push

```bash
git add -A
git commit -m "fix: ... (vX.Y.Z)"
git tag -a vX.Y.Z -m "localvault X.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Pushing the `v*` tag triggers `.github/workflows/release.yml`, which:
runs tests → builds the gem → **`gem push` to RubyGems** → updates the
`inventlist/homebrew-tap` formula → smoke-tests the install from both
RubyGems and Homebrew.

**Do not `gem push` manually** — it collides with the CI push (the version
already exists by the time CI runs).

## 4. Upgrade the local install

The `localvault` on your PATH is the Homebrew build, so upgrade via brew
(not `gem install`):

```bash
brew update
brew upgrade inventlist/tap/localvault
localvault version   # confirm x.y.z
```

## 5. Announce

Post a release tweet from the **@Invent_List** brand account using the
inventlist CLI:

Always include **both** install paths (`brew install inventlist/tap/localvault`
and `gem install localvault`) and the tool page URL
https://inventlist.com/tools/localvault:

```bash
inventlist tweet "localvault X.Y.Z — <what changed>.

brew install inventlist/tap/localvault
gem install localvault

https://inventlist.com/tools/localvault" --account @Invent_List
```
