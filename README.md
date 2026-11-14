# halti

Keychain-backed secrets for humans and agents on macOS. Values live in the login Keychain, or sealed in a workspace's files (see Workspaces). Agents never get them: they work through `halti mcp`, where halti makes the requests and adds the credentials itself.

Secrets are grouped by **resource**, one thing you sign in to (`github`, `aws`, `app`). A resource has a link, a description and **fields** (`token`, `user`, `password`, `session`, …), each its own Keychain item. What may happen to them is decided by the resource's **policy**, which has no effect until you approve it with Touch ID.

## Install

Requires macOS, Rust (`mise use -g rust@stable`, or rustup), and Node.js for the sandboxed browser. For a Linux server, see On a Linux server.

```sh
git clone https://github.com/deorlovnis/halti.git ~/Git/halti
~/Git/halti/install.sh       # builds, signs, installs /usr/local/bin/halti and the browser runner (root-owned)
halti --help
```

`./install.sh --dry-run` lists everything an install would write, build and name, and changes nothing. To update: `git pull && ./install.sh`. It ends by asking you to approve your policies again, with one Touch ID (see Signing). Never install a debug build: debug builds let tests answer approval prompts.

Boxes (in progress) run agents in VMs made by Apple's [`container`](https://github.com/apple/container/releases) (macOS 26). If it's installed and running (`container system start`), `install.sh` also builds the agent image from `box/agent.Containerfile`, its JVM variant (a JDK and the Kotlin language server) from `box/agent-jvm.Containerfile`, and the browser image from `box/browser.Containerfile`; without it the rest of halti works as before. `mise run e2e-box` tests the VM engine against a real VM.

### Renamed from cred

halti was called cred. Its names are now halti's throughout: the binary `/usr/local/bin/halti` with its runner in `/usr/local/lib/halti`, Keychain items `halti:…`, `~/.config/halti`, `~/Library/Application Support/halti`, the images `halti-agent`, `halti-agent-jvm`, `halti-agent-rust` and `halti-browser`, and inside a box `halti-shim`, `/run/halti`, the stand-in `halti-managed` and the `halti` MCP server, so an agent's tools are `mcp__halti__*` on the Mac and in a box alike. `src/names.rs` lists them. Environment variables are `HALTI_*`; the old `CRED_*` names are still read when the new one isn't set, and refresh scripts get both. `halti run` no longer reads a `.cred` file: name each resource with `-s`.

An install made by cred is left alone: `install.sh` doesn't read or change its items, files, images or running boxes, so both can be on one Mac. Moving a cred install's secrets, approvals and boxes over to halti is a migration that comes later; `src/legacy.rs` keeps the names it will read.

### Signing

macOS asks before an app reads a Keychain item it didn't store, and remembers **Always Allow** per app identity. A plain Rust build is ad-hoc signed, so every rebuild counts as a new app and asks again. Sign with a stable self-signed identity once, and your Always Allow answers survive updates:

```sh
cat > /tmp/halti-cert.cnf <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = halti code signing
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
CNF
cd "$(mktemp -d)"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -config /tmp/halti-cert.cnf -keyout key.pem -out cert.pem
openssl pkcs12 -export -inkey key.pem -in cert.pem -name "halti code signing" -out halti.p12 -passout pass:tmp \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1   # algorithms the Keychain can import
security import halti.p12 -k ~/Library/Keychains/login.keychain-db -P tmp   # no -T: signing must ask
rm -f key.pem cert.pem halti.p12 /tmp/halti-cert.cnf
```

When `codesign` asks to use the key, choose **Allow**, never **Always Allow**: a key anything can use silently lets any program running as you sign a lookalike halti that the Keychain trusts. `install.sh` signs with `HALTI_SIGN_IDENTITY` if set, else "halti code signing". After switching identities, run `halti reseal` so each item trusts only the new halti, then approve your policies again.

Items halti writes itself, policy approvals included, stay tied to the exact build that wrote them: without an Apple Developer Team ID, macOS can't tie them to the signing identity. Approvals are read without allowing a prompt, so after an update they read as missing and every resource is blocked until you approve again. `install.sh` does that at the end. Keychain prompts take your login password; Touch ID only appears in halti's own approval prompts.

### On a Linux server

On x86-64 or arm64 Linux, halti keeps workspaces (see Workspaces): over `ssh -t` you make one, store its secrets, and write and approve its policies, typing the passphrase into the server's terminal; `halti open` checks the passphrase and the files. Boxes don't run on Linux yet, so nothing there uses a workspace's secrets, and the Keychain commands (`halti set`, `policy`, `box`) find nothing there.

`check.sh` needs Rust with clippy and rustfmt (rustup's default profile has both), a C compiler (`build-essential` on Debian), git, Node.js (it checks the browser runner's syntax), and user namespaces that `unshare -Urm` may use: its release tests run in one, and some systems restrict them. Installing needs sudo.

```sh
git clone https://github.com/deorlovnis/halti.git ~/halti
~/halti/check.sh             # must pass on this machine, at this commit, before halti is installed
~/halti/install-linux.sh     # builds and installs /usr/local/bin/halti (root-owned), then warns about sudo and swap
ssh -t server halti ws new acme   # from your Mac
```

Run `install-linux.sh` as the user that runs halti, not as root. `./install-linux.sh --dry-run` lists what it would write and changes nothing. It installs only a commit `check.sh` has passed at on this machine with no changes to the files (`check.sh` writes that commit to `check-passed` in the target folder), and only a build with no test hooks. To update: `git pull && ./check.sh && ./install-linux.sh`.

Nothing that opens a workspace is saved on the server. But the server is someone else's machine. Whoever controls it while it runs (root, or its provider) can take the secrets a halti command reads while it runs (`halti ws set`, `ws ls acme`, `ws policy approve`) and every passphrase typed there, and with a passphrase, every secret of that workspace. Use one workspace per client, and tokens with narrow rights. Against the rest, halti on a server holds only under four conditions. `install-linux.sh` checks the two it can and warns; neither warning stops the install.

- **SSH.** Log in by key only, with password login off. Note the server's host key when you set it up and compare it at your first connection: a passphrase typed to the wrong host is leaked, so treat that workspace's secrets as leaked too. Never `ssh -A` to the server: a broken server could use your forwarded keys elsewhere. A private network (WireGuard, Tailscale) keeps the port off the internet.
- **sudo.** The user that runs halti must not have sudo without a password. halti's approved settings are owned by root so that a program running as you can't change them (see Settings); if sudo asks nothing, that program is root, and can replace `/usr/local/bin/halti`, change the approved settings and catch every passphrase typed later. Some server images set this up for the login user: give the user a password and remove the rule (in `/etc/sudoers.d/`, with `sudo visudo -f`). sudo with a password is weaker than it sounds too: a program running as you can wait for you to type it.
- **Swap.** No swap, or encrypted swap. Tokens and workspace keys in halti's memory can be written to swap, and a copy of the disk taken later then holds them. `install-linux.sh` warns about swap that isn't on a dm-crypt device, a swap file by the disk it is on (zram is memory, and fine). Turn it off with `sudo swapoff -a`, and remove it from `/etc/fstab`.
- **An encrypted data disk.** Keep the workspaces folder on a disk you unlock yourself over SSH after each boot (LUKS), mounted on a folder owned by root, say `/data`. With the disk unlocked and mounted, make a folder on it that only you can open (`sudo install -d -o "$USER" -m 700 /data/halti-ws`) and point `[paths] workspaces` there before you make a workspace (see Settings; on Linux too it is `~/Library/Application Support/halti/ws` otherwise). halti makes the workspaces folder if it isn't there: while the disk is locked, a mount point of root's makes that fail, where one of yours would have the folder made on the system disk. A workspace's secrets are sealed under its passphrase either way, but its audit log and its policy files, which name the sites a client uses, are plain files. A disk that unlocks itself at boot, with a key file or a TPM chip, protects nothing against whoever can boot the server.

Not covered by any of these: the halti program and the approved settings are on the system disk. Whoever can write that disk while the server is off, or use your hosting account (a rescue boot, the console, a reinstall), can replace them and get the next passphrase typed. Protect the hosting account as you would the server. If the server is ever taken over: rebuild it, change every secret of the workspaces on it at their sites, and make each of them again, with a new passphrase.

## Use

```sh
halti set github token --expires 2027-01-31  # hidden prompt; asks for link/description
halti update github token                    # rotate: copy the new token, run this
halti policy edit github                     # write the policy; shows a diff against the approved one
halti policy approve github                  # Touch ID; until then the policy has no effect
halti policy approve                         # all policies, one Touch ID (install.sh runs this)
halti run -s github -- gh api user           # if the policy allows: exported fields as env vars
halti ls                                     # one row per resource, with a summary of its policy
halti info github                            # fields, expiry, refresh, and what the approved policy allows
halti check                                  # expired / expiring within 14 days
halti audit                                  # what agents did through halti mcp (never values)
```

`halti copy RES FIELD` asks for Touch ID. `halti describe RES` edits the link and description, and `halti rm RES [FIELD]` deletes. `halti --help` lists everything.

## Workspaces

A **workspace** keeps one client's secrets apart from another's, sealed in files under its own passphrase. Its boxes use them (see Boxes in a workspace), and nothing else does yet.

```sh
halti ws new acme                          # asks for a new passphrase (or makes one: --generate)
halti ws set acme/github token             # asks as [workspace.approval] says, then the value, typed unseen
pbpaste | halti ws set acme/github token   # or the value piped in; the approval is still asked
halti ws ls acme                           # the resources and fields stored in acme (asks as for open)
halti ws rm acme/github token              # one field; `halti ws rm acme/github` removes every field of github
halti ws policy edit acme/github           # github's policy in acme, in $EDITOR; asks nothing
halti ws policy approve acme               # every policy in acme, shown against what was approved (or acme/github)
halti ws policy show acme                  # which are approved (asks as for open); acme/github prints one
halti ws ls                                # the workspaces (asks nothing)
halti open acme                            # checks the passphrase and the files
halti ws delete acme                       # the workspace and everything in it (not while one of its boxes has a store)
```

- Each command asks for one approval, as `[workspace.approval]` says (see Settings), and if a saved passphrase can't be read, has you type it once more; `--type` has you type the passphrase whatever it says. The value is read only after that, and never shown, logged or taken from an argument.
- A value is text of 1 to 65536 bytes with no control characters but tab and line feed; binary goes in as base64. From a pipe, one trailing line break is dropped and nothing else. Typed, a value is one line, and the tab and escape keys type nothing; pipe in a value that has a line break or a tab.
- Values are kept as `[secrets] store` says: files, one per secret, sealed and named by 64 hex characters, beside a sealed list of what is stored. `halti ws ls acme` says if a secret's file is missing or isn't the one the list names, and how to set it again.
- **Limit:** older copies of a workspace's files, put back together with its pin file, read as they were, older secrets included.

### Policies in a workspace

A workspace's policies are its own: `halti ws policy edit acme/github` writes github's in acme's folder, apart from the Keychain's `~/.config/halti/policy/github.toml`, and an approval in one never counts in the other. A policy in a workspace is what acme's boxes use; nothing else reads it.

- Approving asks as `[workspace.approval] policy` says, never `none`, and seals the sha256 of each policy's text in the workspace, with its secrets' list. What is shown before you approve is what is sealed. `halti ws policy approve acme` shows each policy against the copy kept when it was last approved: `new` with its whole text, `changed` with a diff, or `unchanged`. If a copy isn't what was approved, nothing is approved, and `halti ws policy approve acme/github` shows that one whole. With a password manager, the Touch ID window or sudo names the policies being approved, the first three with the start of their sha256, then how many more.
- `halti ws policy show` says `approved`, `not approved`, `changed since approval`, or `approved, no file`: the file's bytes now, against the sealed sha256.
- A policy in a workspace is 1 byte to 64 KiB of plain ASCII (a host with other letters is written in its `xn--` form; a line that is only a comment may have other letters, but no control or invisible character), can't use `[refresh]` yet, and keeps `[run]` and `[agent]` as they are when left out. A policy copied from the Keychain's folder passes once its `[run]`, `[agent]` and `[refresh]` are removed or left as the template has them.
- Deleting or narrowing a policy's file revokes nothing: the text approved, written back, is approved again. `halti ws rm acme/github` removes github's secrets and its approval, and keeps the file; approving another text replaces it. `halti ws delete acme` removes the policies with the workspace.
- **Limit:** any earlier state of a workspace's files can be put back, with approvals and revocations as they were then.

### Boxes in a workspace

A workspace's boxes are boxes (see Boxes) whose agent reaches only that workspace's sites and model, with its secrets: never the Keychain's, never another workspace's. Starting one opens the workspace, and that is the only question.

```sh
halti ws box new acme/dev           # its policy in $EDITOR, then one approval: its key, its policy, an empty encrypted store
halti ws box edit acme/dev          # shows what changed from the approved policy; asks nothing
halti ws box approve acme/dev       # until then a changed policy can't start the box
halti ws run acme/dev               # asks as for opening acme; you're in Claude Code, inside the box
halti ws run acme/dev -- bash       # another terminal joins the box that runs, and is asked nothing
halti ws box ls acme                # open or locked, size, last used, sites (asks nothing)
halti ws box log acme/dev           # what went through its door (asks as for opening acme, unless it runs)
halti ws stop acme/dev              # stop and lock; also happens when `run` ends or on Ctrl-C
halti ws box rm acme/dev            # its key, then its store; its policy file stays
```

- `ws box new` and `ws box approve` ask as `[workspace.approval] policy` says, `ws run` and `ws box log` as `open`, and `ws box rm` as `rm`; each takes `--type`. A wrong passphrase, a no, and every check before them change nothing. `[box] engine` and `[box.approval] write` apply as to any box; `[box] keys` and the other `[box.approval]` lines don't: a box's key is sealed in its workspace, and the workspace's lines approve the rest.
- `WSDIR` is the workspace's folder: `[paths] workspaces` (see Settings), then the workspace's id, 32 hex characters. The box's policy is `WSDIR/boxes/policies/NAME.toml`, the file `halti ws box new` and `ws box edit` open in `$EDITOR`, and its store `WSDIR/boxes/NAME.sparsebundle`. Its policy is approved like a workspace's policies: what is shown is what is sealed, and plain ASCII. A box that runs keeps the policy it started with; its sites' secrets and approvals are read again as they change, so `halti ws set acme/github token` or approving github's policy counts at the next request.
- `model` names the workspace's own resource: store a long-lived token for it (`claude setup-token`, then `halti ws set acme/anthropic token`). Refresh doesn't run in a workspace yet.
- A workspace's box mounts only folders in your home that aren't hidden (no `~/.ssh`, `~/.claude`, `~/.config`) and aren't in `~/Library`, nor the home folder itself, as written and as their real path: copy anything else into such a folder first. A folder of another client's in your home is yours to approve or not: halti can't tell whose it is.
- A write a site's `[fetch]` or `[browse]` policy says to ask about is asked with Touch ID, whatever the settings, and the question names the box (`box acme/dev: ...`).
- Its VMs are `halti-wsbox-TAG-NAME` and `halti-wsbrowser-TAG-NAME`, TAG the first 12 characters of the workspace's id, so they never meet halti's other boxes, cred's, or another workspace's. `halti ws delete acme` refuses while a box of acme's has a store or runs, and otherwise removes the boxes folder with the workspace.
- There is no `ws box login`, `export` or `import` yet. To move a client's box here by hand: export its work into a plain folder in your home, run `halti ws box new acme/NAME`, and in the editor put its box policy in place of the template, with a `[[mount]]` of that folder (mode `clone`, which copies it in at the first run). Remove the folder after.

## Settings

halti needs no settings file. `halti config` makes `~/.config/halti/config.toml` from its template the first time and opens it in `$EDITOR`:

```toml
# halti config. edit with: halti config

[approval]
default = "sudo"              # sudo | touchid | passphrase
config  = "sudo"              # a change to this file: sudo | touchid

[paths]
workspaces = "~/Library/Application Support/halti/ws"

[passwords]
manager = "none"              # none | keychain

[secrets]
store = "files"               # files

[workspace]
passphrase = "own"            # own | generate

[workspace.approval]
open   = "passphrase"         # opening a workspace: passphrase | sudo | touchid | none
set    = "passphrase"         # storing a secret in a workspace: passphrase | sudo | touchid
rm     = "passphrase"         # removing secrets from a workspace: passphrase | sudo | touchid | none
policy = "passphrase"         # approving a policy in a workspace: passphrase | sudo | touchid
delete = "passphrase"         # deleting a workspace: passphrase | sudo | touchid | none

[box]
engine = "container"          # container
keys   = "keychain"           # where a box's key is kept: keychain

[box.approval]
run    = "touchid"            # opening a box: touchid | sudo | none
policy = "touchid"            # approving a changed box policy: touchid | sudo | none
write  = "touchid"            # a write the box's policy says to ask about: touchid | none
export = "touchid"            # copying files out of a box: touchid | sudo | none
delete = "touchid"            # deleting a box: touchid | sudo | none
```

- The file is plain ascii text: names without quotes, values in double quotes on one line, and no backslash.
- An edit has no effect until approved, and `[approval] config` says how. `sudo`, the default, asks for your password and writes the approved copy as root to `/Library/Application Support/halti/approved/<uid>.toml` (`/etc/halti/approved/` on Linux), where a program running as you can't change it. `touchid` (on a Mac) approves later changes with Touch ID, kept in the Keychain like a policy's approval; if that approval goes missing, the settings last approved with sudo are back in effect. It can't be `none`.
- `halti config` shows what your edit changed, on the terminal where sudo asks, then approves it. `halti config --show` prints the settings in effect, `halti config --default` the template. Until a change is approved, every workspace command says so.
- With no approved copy, or one someone other than root could change, the template is in effect.
- `[approval] default` is for any action without its own line, except a box's and a workspace's. `[paths] workspaces` is where new workspaces go: a folder that isn't there yet, an empty one only you can open, or one halti made. Ones already made stay where they are, and aren't listed until you move them there. `[workspace] passphrase` says whether `halti ws new` asks for a passphrase of your own or makes one (`--own` and `--generate` say otherwise).
- `[passwords] manager = "keychain"` (on a Mac) saves each new workspace's passphrase in your login Keychain once `halti ws new` has made it. `[workspace.approval]` says how you approve opening a workspace (and listing its secrets, `halti ws ls NAME`, and its policies, `halti ws policy show`), storing a secret in it, removing secrets from it, approving its policies, and deleting it: `passphrase`, the default, has you type it, and the saved copy isn't used; `sudo`, `touchid` or `none` has you approve that way, or not at all, and halti takes the passphrase from the Keychain. Those three need a manager, and `set` and `policy` can't be `none`. `--type` on `halti open`, `halti ws ls NAME`, `halti ws set`, `halti ws rm`, `halti ws policy approve`, `halti ws policy show`, `halti ws delete`, `halti ws run` and `halti ws box new`, `approve`, `rm` and `log` always has you type it. The copy is kept in your login Keychain only, whatever your default keychain is. If the saved copy can't be read (after a halti update, say, or while your login Keychain is locked), halti asks you to type it once, and `halti open` saves it again. A workspace made before its passphrase could be saved stays typed each time; to have one saved, make the workspace again. halti never shows a Keychain window for a saved passphrase: if one asks to use an item named `halti-ws:...`, choose Deny.
- `[box]` names what runs a box (Apple's `container`) and where its key is kept (the Keychain). `[box.approval]` says what you answer before a box opens, before its changed policy counts, before a write its policy says to ask about, before files are copied out of it, and before it is deleted: Touch ID, your password through sudo, or nothing (`none`). A write is asked while the agent has the terminal, so only Touch ID or `none` can approve it. A box line you leave out is Touch ID, whatever `default` says. A running box keeps the write approval it opened with. On Linux no box runs, so the template has no `[box]` section.

## Policies

`~/.config/halti/policy/<resource>.toml`:

```toml
[run]
mode = "ask"                                   # halti run: allow | ask (Touch ID each time) | deny
export = { token = "APP_TOKEN" }               # fields halti run exports, as env vars

[refresh.session]
from = "firefox:https://app.example.com#session_token"   # read from Firefox Local Storage
                                               # (or firefox-cookie:… / chrome-cookie:… for a cookie)

[refresh.token]
run = "~/.config/halti/refresh/app.sh"          # prints a fresh value

[agent]
consent = "session"                            # Touch ID before an agent session first uses it
consent_minutes = 240                          # ...and again after this long (0: only after a reconnect)

[fetch]
hosts = ["https://api.example.com"]            # the only hosts halti sends credentials to
writes = "deny"                                # requests other than GET/HEAD: deny | ask | allow
auth = "Bearer {token}"                        # header halti adds; the agent never sees it
auth_header = "Authorization"                  # the default
headers = { "x-client-id" = "web" }            # fixed, non-secret headers the site expects

[[tool]]
name = "item"
about = "Get one item"
request = "GET https://api.example.com/items/{id}"
```

- `halti ls` and `halti info` show what the *approved* policy allows. In `ls`, `run:ask fetch browse:ask` means `halti run` asks, requests are allowed (writes denied), and pages may send writes after asking: a mode after a colon is the rule for writes, or for `halti run`. A policy that isn't approved, or changed since, shows as such instead, and none of it applies.
- `halti policy edit` shows what your edit changed compared to the approved version (a colored diff in a terminal) and offers to approve it.
- `halti policy approve` prints the policy and pins its sha256, and each refresh script's, in the Keychain. If the policy or a script changes afterwards, or the approval wasn't written by halti, the resource is blocked until you approve again.
- Refresh scripts get the fields that aren't exported (login, session) as `HALTI_<FIELD>`, and as `CRED_<FIELD>` for scripts written before the rename. They run from a private copy of the approved bytes.
- A field refreshes in the last 5 minutes before its exact expiry, on its expiry date if only the date is known, or daily if its expiry is unknown. This happens before `halti run` or an agent uses it, and during `halti check`. JWT values get their exact expiry from the token.
- `from` handles logins only a browser can do (Google sign-in, other SSO): sign in on the site in a browser, and halti reads the session it keeps. `firefox:ORIGIN#KEY` reads a Local Storage key, `firefox-cookie:ORIGIN#NAME` a cookie from Firefox (default profile; `HALTI_FIREFOX_PROFILE` overrides), and `chrome-cookie:ORIGIN#NAME` a cookie from Chrome's Default profile (`HALTI_CHROME_PROFILE` overrides). Chrome encrypts its cookies with a key kept in the Keychain as "Chrome Safe Storage", so macOS asks for your login password the first time halti reads it (Always Allow stops that).

## Agents

Register once:

```sh
claude mcp add --scope user halti -- /usr/local/bin/halti mcp
```

The agent gets these tools:
- `sites`: lists what each approved site allows.
- `fetch(site, method, url, body)`: a request to one of the site's hosts. halti adds the credentials and doesn't follow redirects.
- One tool per `[[tool]]` in the policies.
- The `browse_*` tools, for sites whose policy has a `[browse]` section (see Browsing).

Results are masked: the resource's values, and anything shaped like a JWT. Writes follow the policy's `writes` rule. When the policy asks for consent, a site's first use in a session needs your Touch ID. The consent lapses after `consent_minutes` (default 240; 0 keeps it until the agent disconnects), and the next use asks again.

### Audit log

Every call an agent makes through `halti mcp` is appended to `~/.config/halti/audit.log` once it has run, before the agent gets the result. If the log can't be opened or written (say, its Keychain key is unreadable), the agent gets an error instead. One JSON line per call: time, site, tool, method, URL and decision: `allowed`, `asked:yes` or `asked:no` (you were asked, and answered), or `blocked` (refused by the policy, or failed before an answer). Never values, headers, bodies or typed text. URLs are masked like everything else the agent sees, and lose any user, password and `#fragment`; query values that look like secrets (keys like `token`, `key`, `code`, or long opaque strings) and opaque path segments become `********`.

Each line carries an HMAC over its content and the previous line's, keyed by an item in the Keychain (`halti:_audit/hmac`, created on first use). `halti audit` shows the latest entries (`-n 50` for more); `halti audit --verify` reads the whole log and reports the first line where the chain breaks, so an edited, swapped or removed line shows. Cutting lines off the end can't be seen. Same-user limit: whoever can read the key from the Keychain (a program running as you, with your approval of a prompt) could forge a chain.

## Browsing

For sites an agent should use the way a person does, add a `[browse]` section. halti starts a headless Chromium (one per site, profile in memory only), puts the session into it from stored fields, and lets the agent steer it with `browse_open`, `browse_goto`, `browse_snapshot`, `browse_find`, `browse_click`, `browse_type`, `browse_press`, `browse_back`, `browse_requests`, `browse_screenshot` (if the policy allows it), `browse_fill_credential` (if the policy lists fields) and `browse_close`. The agent gets the page's accessibility tree with element refs, masked. It never gets the login, cookies, storage, request headers, or a way to run JavaScript.

- Pages can be large: `browse_snapshot` takes `compact` (one short line per named element) or `ref` (just that element), and `browse_find(text)` returns only the elements whose name or text match, with their refs.
- After a click (or Enter), halti waits up to 3 seconds for the URL or the page's text to change, so single-page apps return the new view.
- `browse_requests` lists the data requests (XHR/fetch: method and URL, never headers or bodies; query values over 16 characters left out) the pages made, so the agent can find the API behind a view and use `fetch` instead of scraping.
- `browse_fill_credential(ref, field)` types a stored field into an input, for sites without a session to inject. halti does it itself, only for fields the policy lists in `fill`, and only when the page and the input's frame are on the policy's origins. The typed value is masked in everything returned.

```toml
[browse]
origins = ["https://app.example.com"]          # the only sites pages may be opened from
requests = ["https://api.example.com"]         # further hosts the pages may call or load from
writes = "ask"                                 # requests other than GET from pages: deny | ask | allow
allow_writes = ["https://app.example.com/api/telemetry"]   # URL prefixes allowed without asking
fill = ["user", "password"]                    # fields browse_fill_credential may type (not with origins = "*")
start = "https://app.example.com/home"
screenshots = true                             # let the agent see the page as an image (can't be masked)
idle_minutes = 10                              # the browser closes after this long without a call (0: never)
max_minutes = 60                               # ...and this long after it opened, however busy (0: never)
cookies = [{ name = "session", field = "token", domain = ".example.com" }]
local_storage = [{ origin = "https://app.example.com", key = "jwt", field = "token" }]
```

Sites can be exact (`https://app.example.com`), a domain with its subdomains (`https://*.example.com`), or `"*"` for any https site. Requests to other hosts are blocked, service workers are off, and downloads are refused. Cookies only go to the domain the policy names. The runner (`runner/`, pinned `playwright-core`) is installed root-owned by `install.sh`; it uses Playwright's Chromium headless shell from `~/Library/Caches/ms-playwright`.

Writes that pages try without an `allow_writes` rule (a telemetry POST on every page load, say) are blocked or asked about, and remembered without their query or body: `halti info SITE` lists them, so you can add the harmless ones to `allow_writes`. The page tools mention this when a write was blocked.

A browser closes by itself after `idle_minutes` without a call, and `max_minutes` after it opened; the agent then needs `browse_open` again. A `browse_open` waits for your Touch ID when the site's first use in a session needs consent, so it can take as long as you take to answer.

## Boxes

A **box** is an isolated, encrypted place where an agent works: a Linux VM with no network of its own, whose only way out is a door halti keeps. The agent can do any work a person at a computer could (run code, install packages, keep files) but can't see your Mac, your Keychain or any credential. What it keeps is in an AES-256 store whose key lives in the Keychain; deleting the key destroys the box. The door sees every request the agent makes, so a box can read the open web while its writes stay under your rules. Sites that allow browsing get a sandboxed browser in a second VM of the box, with sessions halti keeps sealed in the box's store.

```sh
halti box new research             # policy template in $EDITOR, a new key in the Keychain, an empty store
halti box approve research         # Touch ID (or as [box.approval] policy says); until then the box can't open
halti box run research             # Touch ID (or as [box.approval] run says) opens it; you're in Claude Code, inside the box
halti box run research -- bash     # a shell in the same box (joins it if it's running)
halti box run --temp research      # a throwaway box with research's policy, gone when it stops
halti box ls                       # open or locked, policy status, size, sites, last used, sites with a sealed browser session
halti box login research           # sign in to the box's sites by hand, in a window on the Mac (Touch ID, box stopped)
halti box login research app       # just one site;  --all signs in again to sites that have a session already
halti box log research             # what went through the door: a line per request, chained
halti box log research --verify    # checks the chain; names the first line that was changed or removed
halti box export research work/report.md --to ~/Desktop  # Touch ID (or [box.approval] export); lists each file with size and sha256
halti box import research ~/data.csv                     # copy a file or folder into work/ (box stopped)
halti box stop research            # stop and lock; also happens when `run` ends or on Ctrl-C
halti box rm research              # Touch ID (or [box.approval] delete); deletes the key, then the store
```

`halti policy approve` with no names approves your boxes too, so `install.sh` still needs one Touch ID. If `[box.approval] policy` says otherwise, the resources take Touch ID and the boxes are then asked for that way.

`~/.config/halti/box/<name>.toml`:

```toml
about = "Market research"
run = ["claude"]                        # what `halti box run` starts; `-- CMD` replaces it
image = "halti-agent@sha256:..."        # the system inside, pinned by digest: a new image is a policy change
model = "anthropic"                     # resource whose key halti adds to the agent's model calls
sites = ["github", "app"]               # resources the agent may use through halti; their policies apply
standins = ["GH_TOKEN"]                 # variables set to "halti-managed", for tools that won't start without a token
keep = true                             # false: a new store every run, shredded when it stops, key never kept
cpus = 4
memory = "8G"

[net]
allow = ["*"]                           # the sites the agent's own requests reach: any public https site, or a list like ["https://*.wikipedia.org"]
writes = "deny"                         # requests that aren't reads, to hosts no site covers: deny | ask (Touch ID each) | allow
allow_writes = ["https://api.example.com/search"]   # URL prefixes that may receive writes anyway

[browser]                               # the sandboxed browser, for `sites` whose own policy has a [browse] section
keep_sessions = true                    # seal each site's session when its browser closes, so the next one starts signed in (the default)
downloads = false                       # true: pages may download files, saved on the Mac outside the box (the default is to refuse them)

[[mount]]                               # holes in the box: none unless listed
path = "~/Git/project"
mode = "clone"                          # clone: the agent works on its own copy in work/ | ro: read-only at /mnt/project
```

- A box policy works like a resource policy: no effect until approved, a change blocks the box until approved again, and `halti box edit` shows a diff against the approved version. The approval is kept under the Keychain name `box.NAME` (resource names can't contain a dot, so it never collides with a resource).
- One Touch ID at `run` (or what `[box.approval] run` says) opens the box and covers consent for its `sites`. Their own policies still decide hosts, writes and what may be browsed. `model` names a resource with a `[fetch]` policy: halti forwards the agent's model calls to its host with the real key, and the agent only has a stand-in. Joining a running box (`run NAME -- CMD` from another terminal) asks nothing more.
- **Reads and writes.** The door ends TLS for the agent's connections, with a certificate authority made for that box and trusted only inside it (its key is sealed in the box's store, in a folder no VM mounts, and installed in the VM on each run), and judges each request. Sites are still verified against the usual public roots: one whose certificate doesn't check out gets a `502`. Reads (GET, HEAD, OPTIONS, and the POST that `git fetch` and `git clone` send to `.../git-upload-pack`) go to any site `allow` lets the box reach. Every other request is a write, and so is anything that asks to switch protocols (WebSocket). A write to a host no `sites` entry covers follows `[net] writes`; `allow_writes` lists URL prefixes that may receive writes whatever `writes` says (`https://api.example.com/search` covers `/search` and `/search/x`, not `/searching` or another host that starts alike; `/..` is resolved first). A refused request gets a `403` that says why, and the connection stays usable. With `ask`, a write to such a host waits for your Touch ID, which names the box, the method and the URL with secrets masked (`[box.approval] write = "none"` lets it through without asking). A WebSocket can't be carried through the door yet, so it is refused even where writes are allowed. `rw` mounts aren't offered: files come in with `clone` or `import` and go out with `export`.
- **Credentials for any tool.** On the hosts of a `sites` entry (its `[fetch] hosts`), the door adds the site's `auth` header and fixed `headers` to every request, whatever tool sent it, replacing anything the agent sent; the site's `writes` rule decides writes there instead of `[net]`. The agent never holds the token: `standins` sets variables such as `GH_TOKEN` to `cred-managed` so tools that insist on one start, and the door puts the real credential on the wire. The site's policy is read from its approved copy at each request: a policy that changed or was revoked gives no credentials, and its writes fall back to `[net]`. Answers from those hosts are masked with the site's stored values as they stream (a value split across reads is still found), are sent chunked because masking changes their length, and are asked for uncompressed; a site that compresses anyway is refused with a `502`, since halti can't mask what it can't read. Other hosts' answers pass as they are.
- **The log.** `halti box log` shows one line per request (time, host, method, URL with tokens and long ids masked, status, bytes, decision: `allowed`, `asked:yes`, `asked:no`, `blocked:<why>`), never headers or bodies, along with a line per connection and per export and import. Each line carries an HMAC over itself and the line before, with a key derived from the box key, so `--verify` shows a line that was edited or taken out of the middle. Cutting off the end can't be seen. A log from before it was chained stays readable; its lines are reported as unchecked.
- The `Host` header of every request must be the host the connection is for; otherwise the request is refused and the connection ends, so a connection to one allowed host can't be used to ask another.
- **Browsing in a box.** A box's `sites` that have a `[browse]` section get the same `browse_*` tools as above, but the browser runs in a VM of the box, never on the Mac: it has no network either, and reaches only what the site's `[browse]` `origins` and `requests` allow, through the door. Each `browse_open` is a separate browser with its own profile, so sites never share cookies. The box's Touch ID at `run` is the consent. Outside a box `halti mcp` still runs the browser on the Mac.
- **Downloads.** Pages can't download files unless the policy says `downloads = true`; then each file is saved on the Mac in `~/Library/Application Support/cred/downloads/<box>/<site>/`, outside every store, in a folder only the browser VM mounts. The agent never sees the file: the page tools name it (name, size, sha256), and `halti box import` brings one in on purpose.
- **Sessions.** When a browser closes (`browse_close`, the idle or `max_minutes` limit, or the box stopping), halti takes the session it ends with (cookies and Local Storage, including the new values a site rotated) and seals it in the store's `browser/` folder, one file per site, encrypted with a key derived from the box key for that site alone: a file doesn't open as another site's, and no VM mounts the folder. The next `browse_open` starts from it instead of the Keychain fields, so a site that rotates its session cookie stays signed in across closes and box restarts. The session goes into the browser over a pipe and is masked in everything the agent reads, like the stored values. A file that doesn't open (changed or damaged) isn't used: the site's usual sources are, the audit log gets a `browse_session_unreadable` line, and `browse_open` tells the agent. `keep_sessions = false` writes and reads none. A session nobody signed in to (no cookies, no Local Storage) isn't sealed.
- **`halti box login BOX [SITE]`.** For sites that need you: a visible Chromium on the Mac with an empty profile opens on the site's `start` page (or its one exact origin), you sign in by hand (SSO, two-factor), and closing the window, or Enter in the terminal, seals the session into the box. Touch ID first; the box must be stopped; the session is never printed. Without `SITE` it goes through the box's sites that have `[browse]` and no sealed session yet, one window after another (`signing in to docs (2 of 3)`), sealing each as it closes; Ctrl-C skips just that site, and so does closing a window before signing in. `--all` includes sites that already have a session. `halti box ls` shows which sites have one, by name only.
- Mounts: `clone` copies the folder (with its `.git`) into the box's `work/` on the first run, and the agent keeps its own copy after. `ro` mounts the folder itself read-only. Folders that hold halti's own files, your home folder and `/` are refused.
- **Images.** `halti-agent` has Claude Code, Node, Python, git, `gh` and `uv`, and sends `git@github.com:` remotes over HTTPS, the only way out of a box. `halti-agent-jvm` adds Temurin 25 and JetBrains' Kotlin language server: pin it as a box's `image` (`container image inspect halti-agent-jvm` gives the digest) for Kotlin and Gradle work, and run `claude plugin marketplace add anthropics/claude-plugins-official`, then `claude plugin install kotlin-lsp@claude-plugins-official`, once in the box for code intelligence (the first import of a large Gradle project takes minutes; until it ends the server only knows the file it has open). The JVM ignores the proxy variables, so halti also sets `JAVA_TOOL_OPTIONS` to the door's proxy; the image keeps Java's truststore in step with the box CA. `halti-agent-rust` adds a C toolchain and Rust 1.92 with clippy, rustfmt and rust-analyzer, pinned the same way. All three have Docker Engine, which runs only in a box whose policy says `docker = true`; Testcontainers then works as it does on a laptop. `rosetta = true` adds Rosetta to the VM, for x86-64 images with no arm64 build. Pulls go through the door, so allow the registry (`registry-1.docker.io`, `auth.docker.io`, `production.cloudfront.docker.com`).
- Inside, `/home/agent`, `/work` and `/downloads` are folders of the store; `/tmp` is memory. The agent starts in `/work`. On each run halti makes sure Claude Code's settings skip the web-fetch check and know halti's tools (`halti-shim mcp`), keeping anything else the agent put in those files.
- The store is an APFS sparse bundle in `~/Library/Application Support/halti/box/`, opened with the key on `hdiutil`'s stdin into a private folder, hidden from Finder and Spotlight, and only while the box runs. A store never shrinks when files are deleted (`hdiutil compact` doesn't work on APFS images).
- `export`, `import` and `rm` need the box stopped, because halti doesn't touch a folder a VM has mounted (and a running agent could swap a link in the folder while it is read). `export` copies regular files only, never follows links, and logs each file in the box's log. `log` reads an open box without asking.
- `halti box rm` warns that Time Machine may still hold encrypted copies of the store; restored together with a Keychain from before the removal, which has the old key, they would open.
- A crash leaves an attached store or a throwaway store behind; the next `run` or `stop` detaches and deletes them.

## What halti protects, and what it doesn't

- **Protected:** values never reach the agent through halti. They stay in the Keychain, are added to requests by halti, are masked in everything halti returns, and refresh scripts run from approved bytes. Nothing loosens a policy or releases a value without Touch ID.
- **Not protected:** whatever the agent reads (API responses, page text, screenshots) is in its context, and the agent's client may store it. Claude Code keeps tool results, screenshots included, in its session folder under `~/.claude/projects/`. Masking can't reach text inside a screenshot, so leave `screenshots` off for sites whose pages show secrets.
- **Same-user limits:** the agent runs as you. It can't read values silently, but it can cause Keychain or Touch ID prompts. Approve only prompts you expect.

## With Claude Code

Deny direct Keychain and clipboard reads in `~/.claude/settings.json` too:

```json
{ "permissions": { "deny": [
  "Bash(security find-generic-password:*)",
  "Bash(security find-internet-password:*)",
  "Bash(security dump-keychain:*)",
  "Bash(security export:*)",
  "Bash(halti copy:*)",
  "Bash(pbpaste:*)"
] } }
```

Metadata (never values) is kept in `~/.config/halti/index.json`. `HALTI_WARN_DAYS` sets the warning window (the old `CRED_WARN_DAYS` still works). The home folder is the one your user account names (the passwd entry), not `$HOME`, and no variable moves halti's files. A user without one (a container run with `--user N`, say) can't run halti.

## Development

```sh
./check.sh           # format, clippy, all tests that need no human, and a release build's check: run before pushing
./check.sh install-hook   # once per clone: git runs ./check.sh refs before every push
mise run check       # the same
mise run e2e         # end-to-end tests: the built binary, a local test site, `halti run` and `halti mcp`
mise run e2e-opt-in  # also the sandboxed browser, and one real Touch ID approval (you tap)
mise run macos-check # on a Mac: all a Mac alone can check, with one report
```

`mise run macos-check [--no-vm] [BRANCH]` (`./macos-check.sh`) is the check to run on a Mac for code written elsewhere. It checks out BRANCH from origin if one is named, then runs `check.sh`, the box store tests against real `hdiutil`, and the engine and door tests in real VMs (not with `--no-vm`, or without Apple's `container` running). It asks once, at the start, whether to run the steps that need a finger, and skips them in a VM, without an enrolled Touch ID or outside a terminal. Every step runs whatever failed before it. The report gives the commit, the versions, each step's result and a failed step's output in full; it is printed and saved in `~/Library/Application Support/halti/checks/`. If an install made by cred is on the Mac, the check lists its boxes, VMs and images before and after, and fails if they differ.

This repo is public, so `check.sh` first refuses any tracked file, and `./check.sh refs A..B` any commit message in a range, that cites private planning: issue tracker IDs, milestone and plan codes, local design notes or decision records. Those stay in the tracker. `docs/` is ignored for the same reason.

`cargo test` runs the unit tests and the same end-to-end tests. Debug builds keep Keychain items in a temp folder when `HALTI_TEST_KEYCHAIN` is set and take `HALTI_TEST_APPROVE=yes|no` as the Touch ID answer, so those tests need no human and never touch your Keychain. A debug build never runs sudo: `HALTI_TEST_SUDO=yes|no` answers for it, and keeps the approved settings in the debug build's own config folder. These test hooks, and `HALTI_INDEX`, `HALTI_POLICY_DIR` and `HALTI_BOX_DIR`, which move the files, are compiled only into builds with the debug profile (the `halti_dev` cfg that `build.rs` sets), never into release builds, even ones with debug assertions turned on or `--cfg halti_dev` passed in by hand (that fails to compile). Debug builds honour `$HOME`, keep their files in `~/.config/halti-dev` and `~/Library/Application Support/halti-dev`, apart from an installed halti's, and say so on stderr every time. `halti build-info` says how a binary was built; `check.sh` builds a `ci-release` profile (release without link-time optimisation), requires `debug_assertions=false halti_dev=false` from it, and runs it with every hook set to see it ignore them (`tests/release.rs`, Linux only). `tests/source.rs` lists every `HALTI_*` variable and who reads it, and fails on a new one, on a hook keyed to `debug_assertions`, and on any change to the macOS-only code, which can't be built on the Linux host. The opt-in tests are `#[ignore]`d (`HALTI_E2E_BROWSER=1 cargo test -- --include-ignored` runs the ones that start the runner, including a session that a local site rotates on every visit surviving close and a box restart): the browser ones need `npm ci` in `runner/` and Playwright's Chromium (`install.sh` fetches it), and the Touch ID one uses the real Keychain with a throwaway resource name and removes it afterwards.

On Linux, debug builds have the first light of a sandbox engine, outside the box commands: `halti box sh --engine sandbox [--tool PATH]... [-- CMD]` runs CMD (bash without one) as namespace root in new user, mount, network, PID, IPC and UTS namespaces. The box has only `lo`; a tmpfs root with the host's `/usr` and the system folders beside it, a few named `/etc` files and the tools (`claude` by default, and each tool's folder is on `PATH`), bound read-only; sized tmpfs folders for `/tmp`, `/home/agent` and `/run`; a minimal `/dev` with its own `devpts`; and nothing else of the host, whose root is detached after `pivot_root`. Where the kernel won't mount the box a `/proc` of its own (a host whose `/proc` has covered parts, as in a container), it gets the host's, bound read-only, and says `host /proc visible`. The box's inits get no environment but `TERM`, no fd but stdio, and start in `/`, not your folder; they're non-dumpable, so the box can't read theirs through `/proc`. There's no store, door, Landlock or seccomp yet. Namespace root can remount a read-only bind read-write, so a tool you own, the native installer's `claude` included, can be rewritten from the box until the command gets a nested user namespace of its own. vsock isn't blocked yet (it reaches the hypervisor where there is one); seccomp closes it. Its escape tests are in `tests/sandbox.rs`: `bash` and `claude --version` run; the only network device is `lo`; TCP to the host's loopback fails; a planted file outside the bind set is missing; the folder, environment and fds of the caller don't reach the box; `mountinfo` has no host root; every `/proc` mount is read-only; nothing is left running or mounted after exit; and a missing command exits 127, one that can't run 126. They skip where user namespaces aren't allowed, and `check.sh` lists which ran.
