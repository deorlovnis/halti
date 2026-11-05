#!/bin/sh
# Build, sign and install halti as /usr/local/bin/halti, and its browser runner in
# /usr/local/lib/halti/runner, owned by root so nothing running as you can replace them.
#
# The signing key asks before every signing: choose "Allow", never "Always Allow". Otherwise
# any program running as you could sign a lookalike halti that the Keychain trusts. Without the
# identity the build is installed ad-hoc signed, with a warning. See README "Signing".
set -eu
cd "$(dirname "$0")"

# Names from before halti was renamed from cred, which an existing install still depends on
# (src/legacy.rs says what depends on each). The identifier is permanent; the rest move with
# the workspace migration.
identifier=com.deorlovnis.cred
old_identity="cred code signing"
agent=cred-agent
browser=cred-browser
config="$HOME/.config/cred"

# HALTI_SIGN_IDENTITY, else CRED_SIGN_IDENTITY, else "halti code signing", unless only the old
# one exists.
identity="${HALTI_SIGN_IDENTITY:-${CRED_SIGN_IDENTITY:-}}"
if [ -z "$identity" ]; then
  identity="halti code signing"
  if ! security find-identity -p codesigning | grep -qF "\"$identity\"" &&
    security find-identity -p codesigning | grep -qF "\"$old_identity\""; then
    identity="$old_identity"
  fi
fi
dest=/usr/local/bin/halti

cargo build --release
if security find-identity -p codesigning | grep -qF "\"$identity\""; then
  echo "macOS asks to use the \"$identity\" key: choose Allow, not Always Allow."
  codesign --force --sign "$identity" --identifier "$identifier" target/release/halti
else
  echo "warning: no '$identity' signing identity; installing ad-hoc signed (Keychain will ask again after each update)" >&2
fi
echo "Installing $dest (sudo asks for your password)."
sudo install -d -o root -g wheel -m 755 "$(dirname "$dest")"
sudo install -o root -g wheel -m 755 target/release/halti "$dest"
echo "installed $dest"

# The browser runner (halti's sandboxed browsing), with its pinned playwright-core, root-owned too.
runner=/usr/local/lib/halti/runner
(cd runner && npm ci --ignore-scripts --no-audit --no-fund --silent)
node runner/node_modules/playwright-core/cli.js install chromium-headless-shell >/dev/null
sudo rm -rf "$runner"
sudo install -d -o root -g wheel -m 755 "$runner"
sudo cp -R runner/runner.mjs runner/package.json runner/package-lock.json runner/node_modules "$runner/"
sudo chown -R root:wheel "$runner"
echo "installed $runner"

# Before the rename these were /usr/local/bin/cred and /usr/local/lib/cred. A host MCP
# registration still names the old binary, so it has to be added again.
if [ -e /usr/local/bin/cred ] || [ -L /usr/local/bin/cred ] || [ -e /usr/local/lib/cred ]; then
  sudo rm -rf /usr/local/bin/cred /usr/local/lib/cred
  echo "removed the old cred; if Claude Code runs it as an MCP server, add it again: claude mcp add --scope user halti -- $dest mcp"
fi

# The image of the agent VM for boxes, built with Apple's container. Only boxes need it, so a
# missing or stopped container is a note, not a failure.
if ! command -v container >/dev/null 2>&1; then
  echo "note: Apple's container isn't installed, so boxes won't run: https://github.com/apple/container/releases" >&2
elif ! container system status >/dev/null 2>&1; then
  echo "note: container's system isn't running; run 'container system start', then install.sh again to build the agent image" >&2
elif container build -f box/agent.Containerfile -t "$agent" box; then
  echo "built the agent image $agent"
  # The JVM variant (a JDK and the Kotlin language server), from exactly that build. The builder
  # looks a digest up on Docker Hub, so it gets the <agent>:<hex> tag halti itself runs images by.
  digest=$(container image inspect "$agent" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[0].configuration.descriptor.digest))')
  container image tag "$agent" "$agent:${digest#sha256:}"
  if container build -f box/agent-jvm.Containerfile -t "$agent-jvm" --build-arg "AGENT=$agent:${digest#sha256:}" box; then
    echo "built the JVM agent image $agent-jvm"
  else
    echo "warning: building the JVM agent image failed; boxes pinned to $agent-jvm won't run until it builds" >&2
  fi
  if container build -f box/agent-rust.Containerfile -t "$agent-rust" --build-arg "AGENT=$agent:${digest#sha256:}" box; then
    echo "built the Rust agent image $agent-rust"
  else
    echo "warning: building the Rust agent image failed; boxes pinned to $agent-rust won't run until it builds" >&2
  fi
else
  echo "warning: building the agent image failed; boxes won't run until 'container build' of box/agent.Containerfile works" >&2
fi
# The browser VM's image: halti's runner and Chromium for the box's sites. Built with the repo as
# the context (.dockerignore keeps the rest out). Needed only by boxes with sites that browse.
if command -v container >/dev/null 2>&1 && container system status >/dev/null 2>&1; then
  if container build -f box/browser.Containerfile -t "$browser" .; then
    echo "built the browser image $browser"
  else
    echo "warning: building the browser image failed; boxes can't browse until 'container build' of box/browser.Containerfile works" >&2
  fi
fi

# Keychain items are tied to the build that wrote them, so a new halti can't read the old
# approvals silently: approve the policies again, with one Touch ID for all of them.
if [ -n "$(ls "$config/policy/"*.toml "$config/box/"*.toml 2>/dev/null)" ]; then
  echo "Approve your policies again (Touch ID):"
  "$dest" policy approve || echo "skipped: run 'halti policy approve' to re-enable your sites" >&2
fi
