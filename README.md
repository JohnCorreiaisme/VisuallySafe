# Visually Safe

**A helpful antivirus companion.** Visually Safe shows you, at a glance, what has been checked and what is safe. Every file and folder gets a clear badge: a green tick when it has been scanned and is safe, yellow when it deserves a look, red when it is dangerous. It sits on top of Microsoft Defender and makes it easy to use, made for people who find computers confusing. A family member or carer can set it up for someone else.

## Watch how it works

https://github.com/user-attachments/assets/2d20e1f3-8236-4516-854b-4a06de39bbb2

It works **alongside Microsoft Defender and does not replace it.** It is not made by, endorsed by, or connected to Microsoft.

Works on Windows 10 and Windows 11.

## What it does

- **Boxes on your icons**: a swirling ring while a file is checked, then a green tick (checked and known to be safe), a grey "?" (checked, but nothing is known about it), a yellow "!" or a red cross. You can see at a glance what is safe.
- **Scan map**: every folder drawn as a node, so you can see what has been scanned, what has not, and where anything was flagged.
- **"Is my computer okay?"**: a green, yellow or red answer taken from Windows' own protection status. A *Fix it* button updates Windows' protection and starts a Windows scan.
- **Plain-words reports**: scans starting and finishing, and anything Windows or Visually Safe finds, in everyday words. The family member can get an email.
- **Twice-a-week check** (Mondays and Thursdays): updates the protection and checks the Desktop and Downloads. It also notices new programs that set themselves to start with Windows.
- **Optional helper wizard** (can be turned off): ask anything, by typing or speaking. Answers come from an AI you choose that runs on your own PC (LM Studio, Ollama and similar), so nothing is sent to a company.
- **Extra checks of its own**: file fingerprints against public lists, YARA rules, and a small on-device model. These are a second opinion, not a replacement for Windows' protection.

## Updates

From version 1.0.90 on, Visually Safe checks GitHub for a newer release every few hours. If there is one, it downloads the installer, checks it against the fingerprint (SHA-256) published with the release, and shows a big "A new version is ready" window. Nothing is installed until you click **Update now** and say Yes to the Windows permission box. Your settings and history are kept. Turn it off, or check right away, from the tray menu: *Update automatically* and *Check for updates now*.

## Who answers the wizard

On the AI helper page, **The wizard answers using** lets you choose: Automatic (a local AI such as LM Studio or Ollama if one is running, otherwise his built-in answers), your local AI, **Claude Code**, or **Codex**. Claude Code and Codex are run only to answer in words: no tools and no file access.

## Install

Run **VisuallySafeSetup** and follow the pages. It explains the Windows permission box before it appears, asks who the wizard is for (so a family member can set it up for someone else), and puts Visually Safe in Program Files with a Start menu entry. Remove it later from Windows Settings, then Apps. Your settings are kept.

Windows may show "Windows protected your PC" because the installer is new and not yet signed: click *More info*, then *Run anyway*.

Build the installer yourself with `python tools/build_setup.py` (needs the .NET SDK). It writes `dist/VisuallySafeSetup-<version>.exe`.

## Support

Visually Safe is free. If it helps someone you care about and you would like to say thanks, you can [buy me a coffee on Ko-fi](https://ko-fi.com/johncorreia9791). Donations are never required and unlock nothing.

[![Support Visually Safe on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/johncorreia9791)

## Credits

The wizard character was made with Nano Banana and Tripo.

---

Visually Safe also includes a small background file checker. It is a second opinion that runs
alongside Windows Defender; it does not replace it.

## Run

    bin\VisuallySafe.exe

A shield appears next to the clock. Left-click opens the dashboard; right-click has
Protection on/off, Pause, Quick scan, Scan a file, Start with Windows and Exit.

## Build

    dotnet build -c Release -o bin

Targets .NET Framework 4.8, which ships with Windows 10 and 11, so the exe needs nothing installed.

## How a file is judged

When a program, script, macro document, shortcut or archive lands in a watched folder
(Downloads, Desktop and Startup by default), or a program starts running:

1. Your own allow list / block list (by SHA-256).
2. Valid, trusted digital signature (in the file, or in a Windows catalog), or a Microsoft
   Store app -> Safe.
3. Online, sending only the hash: Team Cymru Malware Hash Registry (capped at 1.5 s),
   MalwareBazaar (only if you add a free key), CIRCL hashlookup -> Malware or Known good.
4. Nobody knows it: the YARA engine (`bin\yara\yara64.exe`, VirusTotal YARA 4.6.0) checks it
   against the YARA-Forge "core" rule set (`bin\yara\core.yar`, ~5,000 rules) plus your own
   rules in `%LOCALAPPDATA%\VisuallySafe\rules\*.yar`. A rule with `score` 80+ in its meta means
   Malware (quarantined); lower means Suspicious. Works on scripts too.
   Rule updates: once a day (first check 2 minutes after start, only while "Check files online"
   is on) Visually Safe asks GitHub for the newest YARA-Forge release. A newer core set is
   downloaded, test-compiled, and only then swapped in as `%LOCALAPPDATA%\VisuallySafe\core.yar`
   (it wins over the bundled copy). Settings shows the rules version and has an "Update rules" button.
5. Still nobody knows it, and it is a program: the offline AI model (`bin\visuallysafe.model`, 1.4 MB)
   scores it. 90% or more marks it Suspicious; lower scores are shown in Activity.
   Trained on EMBER 2018: at 90% it caught 78% of unseen malware with 0.73% false alarms on
   the test set, and 0 of 210 real programs on this PC were flagged.
6. Simple rules (double extension, hidden program, packed contents, Startup folder...)
   -> Suspicious or Unknown.

Known malware is moved to quarantine (stored scrambled so it cannot run). Suspicious
files only raise an alert.

## Programs as they start

Visually Safe checks the process list every second (no admin rights needed) and runs each new
program through the checks above; programs that were already running when Visually Safe started
are checked too. Judged programs are remembered by path, size and date (`programs.tsv`) so they
aren't re-hashed every launch. A program judged Malware is stopped (by its process ID, after
re-checking its path) and quarantined, typically about 2 seconds after it starts. Safe programs
stay out of Activity; first sightings of unknown programs are listed. Visually Safe's own folder
is skipped.

## Network page (needs administrator rights)

Live download and upload per program from Windows' kernel network events (TCP and UDP, so
browser QUIC traffic too), with a one-minute graph per program and totals at the top.
"Block internet" adds two Windows Firewall rules (inbound and outbound, group "Visually Safe") for
that program; "Unblock" removes them. Connections a program already has open may continue
until it restarts.

"Turn on network monitor" restarts Visually Safe as administrator (one Windows prompt). While it
runs as administrator, "Start with Windows" uses a logon scheduled task with highest rights and
no time limit, instead of the Run key.

## Dealing with flagged files

Activity shows, for the selected file, why it was flagged and what to do. Buttons (and a right-click menu):
Quarantine, Delete (permanent, asks first), Mark as safe, Show in folder, Look up online (opens the
file's SHA-256 on VirusTotal; only the hash is in the link). Files that need action are tagged
"Needs action", the sidebar shows a dot, and "Quarantine all N that need action" handles them in one go.
The Quarantine page explains each file and offers Restore, Delete forever, Delete all and Look up online.

Deleting from Quarantine overwrites the file with zeros and deletes it, retrying if something has it
open; the list entry only goes once the file is really gone, and a failure is shown (older versions hid
it and could leave the file on disk). "Delete all" also removes leftover files that have no list entry.

## AI helper

Finds AIs running on this PC (LM Studio :1234, Ollama :11434, Jan :1337, GPT4All :4891,
text-generation-webui :5000, KoboldCpp :5001, llama.cpp/LocalAI :8080, vLLM :8000; localhost only, nothing
leaves the machine) and lists their chat models. "Ask AI" sends Visually Safe's report (what needs action,
recent checks, quarantine, rootkit findings, busiest network programs) with a fixed system prompt.
The AI answers with an explanation plus a JSON list of proposed fixes, which appear as tick boxes.
Allowed types: quarantine, delete, mark_safe, restore, delete_quarantined, block_internet,
unblock_internet, add_safe_folder, run_rootkit_check. Every proposal is checked against Visually Safe's own
log (unknown files, anything under C:\Windows, too-broad folders and unknown types are shown as Rejected),
nothing is ticked by default, and nothing runs until you click "Apply approved" and confirm.
"Copy prompt for any AI" puts the same prompt on the clipboard (it contains file names and paths, so
only paste it into an AI you trust) and "Paste AI's reply" reads the answer back into the same approval list.

**Alt+click AI fix.** Alt+click a row on the Rootkit check, Activity or Quarantine page (or choose "AI fix…"
in Activity's right-click menu). Visually Safe asks the AI chosen on the AI helper page (or the first one it
finds) about that one item, with the whole report as context, then shows a Yes/No box with what the AI
found and exactly what will be done. Only actions about the selected item are allowed (at most 2), and
all the usual safety checks apply. Besides the actions above, a rootkit finding that is a Run-key startup
entry can be removed (`remove_startup_entry`; a copy is saved to `startup-removed.tsv`), and files the
rootkit check points at can be quarantined or deleted. Drivers under C:\Windows are never touched, so for
those the AI can only explain what to do by hand.

## Screen saver

Settings > Screen saver. **Deep-scan slowly when I'm away** starts a full-screen display when the PC has been idle
for the time you pick (1 to 30 minutes; not while a game or video is full screen, not on battery). **Use Visually Safe
as the Windows screen saver** registers `VisuallySafe.scr` (a copy of the exe) in Windows' own screen saver setting
and remembers what was there before so turning it off puts it back; Windows then decides when it starts (and
Visually Safe's own idle timer is switched off). **Start screen saver now** and the tray menu start it instantly.
Moving the mouse or pressing a key ends it.

While it runs: the Scan map fills the screen. The folder being deep-scanned pulses, the file glows with its name,
and a wave spreads outward along the links to neighbouring folders as the scan goes; folders gain a green aura as
more of their files are deep-scanned. Behind the graph every live internet connection is an orb around the screen
edge (program and host name), with blue particles flowing in for downloads and amber ones flowing out for uploads
(exact per-program speeds when the network monitor is on, otherwise the overall speed shared out).

The **deep scan** examines every file in the map (watched folders and everywhere programs were scanned), running
at the lowest CPU and disk priority, resting three times as long as each file took and pausing while anything
else is using the processor (above 40 percent); it stops the moment you are back and resumes next time (progress
is kept in `ledger.tsv`). On top of the normal checks it adds: YARA on every file type, the offline AI model on
every program (signed ones need a higher score), program structure checks (packer sections, scrambled sections,
odd entry points, hidden payloads), NTFS hidden data streams, script behaviour patterns (encoded PowerShell,
download-and-run, hidden windows, deleting backups), and a look inside zip files and Office files (disguised
names, macros in macro-free formats, compression bombs, programs inside checked against your block list and YARA).

When the deep scan has nothing left, and **Defragment the hard drive after the deep scan finishes** is on (needs
administrator rights; skipped if done in the last 3 days), the saver switches to the classic block map and runs
Windows' own `defrag /O`, which defragments a hard disk and only re-trims a solid-state drive.

**Moving blocks.** On a hard disk the block map is real: every 12 seconds while a defrag runs it re-reads where each file now
sits, and blocks that moved glide from their old place to the new one. On a solid-state drive (where Windows only trims and
nothing really moves) it shows an illustration instead, clearly labelled: every file's blocks lift out of the mess and slide
into order, then scatter and repeat. The Defrag page has a **Preview** button to watch the illustration any time.

## Defrag page

Maps a drive straight from NTFS (cluster usage bitmap plus each file's extents; first 40,000 files found,
breadth-first) into a 120 x 40 block map: each block takes the colour of the file that owns most of it, dark is
free space, blocks that just changed flash, and a read/write head sweeps while a defrag runs. Hover a block to
light up that file and draw a line through its pieces. **Analyze** runs `defrag /A`, **Defragment now** runs
`defrag /O` at low priority and refreshes the map every 40 seconds; both need administrator rights.

## Fix with Claude Code or Codex

Visually Safe can hand a problem to Claude Code (`claude`) or Codex (`codex`) installed on this PC. Use **Fix with
agent** in an item's Properties window (Alt+click), or on the AI helper page to hand over everything. Visually Safe
finds the programs on PATH and in their usual install folders. Before anything starts a box shows the agent, how
it will run, and the exact instructions it will be sent (they go to Anthropic/OpenAI through the agent you are
signed in to). Modes: **terminal window** (recommended: the agent asks you before each step), **investigate
read-only** (runs in the background, can't change anything, output shown in Visually Safe), or **fix without asking
again** (background, may change the PC). The instructions are written to `agent-workix-*.md` and tell the agent
to treat everything Visually Safe collected as untrusted data, prefer reversible fixes (update, quarantine) and list
every change with how to undo it. If Visually Safe runs as administrator the agent does too. Headless flags: Codex
`exec -s read-only|danger-full-access`, Claude Code `-p --permission-mode plan|acceptEdits`.

## Alt+click properties and the fix choice box

Alt+click any item (Activity, Quarantine, Rootkit check, Network, Scan map) to open its Properties window:
where it is, size, signature, hash, why it was flagged, and links explaining why it may be bad (VirusTotal,
MalwareBazaar, Hybrid Analysis, MITRE ATT&CK, LOLDrivers, a web search). Below that **Fix…** opens a
choice box (no AI needed): pick exactly one of **Update** (only shown when winget knows
a newer version of the program; it names the package and versions), **Ignore** (mark safe / hide from future
rootkit checks), **Quarantine**, **Delete** or other safe actions, then click Do it. Nothing happens before
that click. Update runs `winget upgrade --id <id> --exact`, so Windows may ask for permission.

## Scan map

A node graph of every watched folder (plus other places programs were scanned): node colour is the worst thing
inside (red malware, amber suspicious, green clean, grey unknown), the ring shows how much is scanned, hollow
means not scanned yet, and removed/quarantined files stay as marked ghosts where they were found. Click a folder
to open it, drag and scroll to move around, Alt+click for properties. While scanning, the folder pulses with a
sweeping arc, the file being scanned glows with its name and a moving beam, and the camera follows it (Follow: on).
It is backed by `ledger.tsv`, a record of every file Visually Safe has examined.

## Net tools

Health check (adapters, DHCP/gateway/DNS problems, router and internet reachability, DNS servers, captive portal,
proxy, firewall state), open ports on this PC with the owning program, device finder (ping sweep + ARP of your
/24), a TCP port scanner (host, IP or CIDR up to /22; top100, ranges or lists; banners; private addresses only
unless you confirm you may test a public one), ping, traceroute and DNS lookup. Everything is logged to
`network-log.txt`; the AI helper's report includes the last network results.

## Rootkit check

Runs without admin rights (more is visible with them). It looks at: every loaded driver (unsigned, missing
from disk, or on the LOLDrivers known-vulnerable/malicious list, downloaded from loldrivers.io and
refreshed weekly while online checks are on); programs hidden from Windows' process lists (three views
cross-checked, plus a direct probe of every process number); startup entries (Run keys, Startup folders,
services, Winlogon, AppInit_DLLs, Image File Execution Options); and the hosts file. It changes nothing.
A kernel rootkit can fool all of it, so the page also has a **Defender Offline scan** button
(`Start-MpWDOScan`: restarts the PC at once and scans before Windows loads; asks first).

## Files

Everything lives in `%LOCALAPPDATA%\VisuallySafe`: `settings.ini`, `history.tsv`, `cache.tsv`,
`programs.tsv`, `quarantine.tsv`, `Quarantine\`, `rules\`, and two lists you can edit by hand,
one SHA-256 per line: `blocklist.txt` and `allowlist.txt`.

## Limits

- The AI model never quarantines on its own; it only raises Suspicious.
- Programs can't be stopped before they start (that needs a kernel driver); they are stopped
  right after.
- Without admin rights malware with admin rights could stop Visually Safe; even with them, it is a
  normal program, not a protected service.

## Developer switches

- `VISUALLYSAFE_DATA=<folder>` environment variable: use a different data folder (for testing).
- `VISUALLYSAFE_NETDEMO=1`: made-up traffic on the Network page, for screenshots without admin.
- `--exit-after N`: quit after N seconds. `--shot <folder>`: save a picture of each page.
- `--show`: open the dashboard on launch.
- `--update-rules`: run one rule update check, result in `<data>\update.log`.
- `--trust <file>`: time the signature check, result in `<data>\trust.log`.
- `--fix-test`: AI-fix logic on a temporary startup entry.
- `--net-tools-test [--devices]`, `--updater-test`, `--props-shot <folder> [--ask-port N]`: tool self-tests and pictures.
- `--deep-test`, `--disk-test` (admin), `--saver-shot <folder> [--seconds N]`, `--saver-reg-test`: screen saver / deep scan / defrag tests. `/s` `/c` `/p` are the Windows screen saver arguments, `--saver` starts it directly.
- `--quar-test`, `--llm-test [--ask <port>]`: delete and local-AI self-tests.
- `--rootkit-test`: run the rootkit check, `<data>
ootkit-test.log`.
- `--net-test <full path to a curl copy>` (admin): traffic + firewall self-test, `<data>\net-test.log`.
- `--features <file> [--out <file>]`: write a file's AI features and score.

## 1.0.4 additions
- **Defrag screen saver**: Settings > "shows: defrag only" (or tray > "Start defrag screen saver now", or the Defrag screen saver button). It shows only the classic coloured block map with moving blocks. Registering with Windows installs `VisuallySafeDefrag.scr` next to the exe. Without administrator rights it shows a clearly labelled demo drive.
- **Real program icon**: `VisuallySafe.ico` (green shield on a dark tile, 16-256 px) is built into the exe, so Explorer, the taskbar, windows and the .scr all use it.

## 1.0.5: fewer false alarms
- UPX-compressed files are no longer flagged for being compressed; soft clues (scrambled data, big installer data, odd entry section) now only count when firmer evidence exists, and the deep-scan bar is 4 points.
- Plug-in style files (.winmd, .mui, .pyd, .node, .ax, .ocx ...) are not called "programs hiding behind an extension".
- A lone AI score no longer reaches Suspicious without other clues.

## 1.0.6
- **Ignore** button on the Activity page: ignore one file, everything in its folder, or all files of that type (they are no longer scanned or flagged). "Stop ignoring anything" undoes all of it. Stored in `ignore.txt`.

## 1.0.7: Family helper mode
Tray > "Family helper mode...". For a relative's computer. Turning it on also turns on the screen saver. A big, friendly helper face with a large speech bubble appears and speaks with the Windows voice:
- greets every few hours ("your kid asked me to watch over your computer, please contact them");
- no network cable / Wi-Fi: asks them to plug it in (checks every 30 s, repeats every 10 min);
- 10 or more unnamed text files ("New Text Document...", "Untitled...") on the Desktop, Documents, Downloads or profile folder, or C: under 10% free: says so (it never deletes anything);
- a big "I need help" button: asks your **remote help server** (a URL you run; Visually Safe POSTs JSON with the computer and user name, and the server answers with `{"code":"123456"}` or just the code), shows the code in huge letters, reads it aloud, and emails it to you. With no server set it opens Windows Quick Assist and emails you that help was requested.
- Email uses your own SMTP server (settings in helper.ini; the password is protected with Windows DPAPI). Nothing connects without the person pressing the button.

## 1.0.8
- Scan map: files that were found and then removed (quarantined or deleted) are now blue instead of red.

## 1.0.9: the scan light
- While Visually Safe checks a file or folder, a light runs around the edge of its icon (in an Explorer window or on the Desktop), then flashes green (clean), blue (nothing to report) or red (found something). It is a see-through window that clicks pass through.
- It happens for every new file or folder that appears in Downloads or on the Desktop, for programs opened from those folders for the first time, and for anything you choose "Scan with Visually Safe" on in the right-click menu (files and folders; on Windows 11 it is under "Show more options").
- Tray menu: "Light up icons while scanning" and "Scan with Visually Safe in right-click menu" turn each on or off.
- Limit: Windows doesn't let a program hold a file back before it opens, so the light and the check run as the file opens; they can't delay it.

## 1.0.10
- The scan light works on many files at once (select several files, right-click > Scan with Visually Safe; Windows only offers the menu entry for up to 15 files at a time. Everything that newly lands in Downloads or on the Desktop is handled automatically).
- When a file is done the moving light goes away and a steady box stays round the icon with a small badge on its corner: green check = nothing found, yellow ! = suspicious, red X = infected. It stays until the icon scrolls away, the window closes or ten minutes pass, and hides while another window covers it. For a folder, the badge shows the worst result of the files inside.

## 1.0.11
- Visually Safe no longer flags its own program files (its install folder and, when built from source, the bin and bin_new folders).

## 1.0.12
- AI helper page: more room above and around the Copy prompt / Paste reply buttons so they are not clipped.

## 1.0.13
- AI helper page: fixed two text lines that were stretched far too wide and covered the top of the Copy prompt / Paste reply buttons.

## 1.0.14: AI update (retired in 1.0.90: Visually Safe now updates itself from GitHub; see below)
An AI agent is told what Visually Safe does (this README and the list of source files) and asked whether Visually Safe needs more as an antivirus; if so it makes up to three small changes. Steps: make a working copy of the source, ask Claude Code or Codex (or copy the prompt for any other AI), then "Check and build".
- The agent works only on the copy: Claude Code gets no command line (Read/Write/Edit/Glob/Grep only), Codex runs in a workspace-only sandbox.
- Visually Safe then lists what changed, warns about new web addresses, new process/registry/download code, and large deletions, builds it, and runs the new program's self-test (a blocked file is caught, a script dropper is flagged, a harmless script and 30 normal Windows programs are not).
- `src/SelfUpdate.cs` and `src/SelfUpdateUi.cs` are protected: an update that changes them is refused.
- Nothing is installed until you click Install. The old source is saved in `%LOCALAPPDATA%\VisuallySafe\update\backup`, the old program is kept as `VisuallySafe.exe.old`, and a hidden watcher puts it back if the new version isn't confirmed healthy after two minutes. The source is updated in the project folder but not committed to git (review with `git diff`).
- Needs the source folder (VisuallySafe.csproj) next to the program and the .NET SDK. The self-test and reading the summary are a safety net, not proof: read what it changed.
- Also fixed: the Family helper window was not scaling on high-DPI screens.

## 1.0.15
- Network page: Alt+click (or right-click) a program to pause its internet for 5 minutes, 30 minutes, 2 hours, or until you unblock it; resume now; open Properties or its folder. Paused programs show "Paused until ..." and are unblocked automatically when the time is up (even after a restart of Visually Safe).

## 1.0.16
- Network menu wording: pausing only affects the chosen program, not the whole PC.

## 1.0.17
- Network menu shows the program's location on disk as a link (opens Explorer on it) and a Copy path item.

## 1.0.19
- Scan light: a green (clean) badge now fades away slowly, but only while the mouse is being moved (a still mouse keeps it lit). Yellow and red results stay lit until the icon scrolls away or its window closes.

## 1.0.20: scanning a whole selection
- Circle or select as many icons as you like on the Desktop or in a folder and press **Ctrl+Alt+S** (or tray > "Scan selected icons now"): every selected file and folder is scanned and gets the scan light. The right-click "Scan with Visually Safe" entry still works, but Windows hides it when more than 15 items are selected and starts one program per item, so use Ctrl+Alt+S for big selections. The right-click path also waits its turn now instead of dropping items when many arrive at once.

## 1.0.21
- Ctrl+Alt+S now scans only the selection in the window you were in (the Desktop or that one Explorer window). Every scan request is logged in `scan-requests.log` in the data folder.

## 1.0.22
- Manual scans (a selection, Ctrl+Alt+S, right-click scan) now run four at a time instead of one after another, and every selected icon starts its scan light straight away (waiting ones keep circling) instead of only the file being checked. Before, each unsigned file waited for its online lookup in turn, so a big selection looked like only one file was scanned.

## 1.0.23
- The scan light is now a progress ring: a ring fills slowly round the icon (blue to green) with the percentage in a tag on its corner, so a big file shows real progress instead of circling forever. Folders fill as their files are checked.
- Yellow = suspicious, red = quarantined. A quarantined file leaves a small stand-in under its old name so its icon stays red and double-clicking it can't run anything. Scan the stand-in with Visually Safe and it re-checks the real file, giving it back only if it is clean now (Restore and Delete in Quarantine also clear the stand-in).
- Works on every Desktop file, folder and shortcut.

## 1.0.24
- Network: the alt-click / right-click menu on a program now also has "Ask AI about this program (repair / is it safe)...", which lists the installed AI agents (Claude Code, Codex) and hands them that program's details.

## 1.0.25
- AI agents can now contain a program: the instructions given to Claude Code / Codex include `VisuallySafe.exe --net-block "path"`, `--net-unblock "path"` and `--stop-program "path"` (one program only, never Visually Safe itself; admin needed for the firewall ones). Every use is logged in `agent-actions.log`.

## 1.0.26
- Net tools: the status line above the results (for example after "Open ports on this PC") was cut off at the bottom by the list; it now shows fully.

## 1.0.27
- Net tools: the results list is now placed below the status line by measurement, so the first result is no longer cut in half.

## 1.0.28
- Net tools: Alt+click (or right-click) a result for "Repair with AI", plus block that program's internet, show it on disk and copy.
- All right-click / Alt+click menus are larger, brighter and have a vivid blue highlight.

## 1.0.29
- Net tools: Alt+click a port result (open ports on this PC, or a port scan) to ignore that port or that program, or stop ignoring it. Common Windows ports (135, 139, 445, 5040, DNS/DHCP, discovery, Windows' dynamic ports) and programs in the Windows folder are ignored by default so they stop showing as warnings; they are still listed, marked "ignored". Your rules are in `net-ignore.txt`, and the menu can turn the built-in list off.

## 1.0.30
- Screen saver stays cool: it redraws at full speed for the first 3 minutes, slower until 15 minutes, then about once a second for the rest of the night, and Visually Safe runs at low priority while the saver is on (back to normal when you leave it).

## 1.0.31 — Shields
New **Shields** page (last item in the sidebar).
- **Ransomware shield**: watches Documents, Pictures, Desktop, Videos and Music. A hidden canary file (`!~visuallysafe-canary.docx`) sits in each folder; if anything changes, renames or deletes it, or about 8 files turn into scrambled data (wrong file header plus noise-like contents) or get renamed to odd extensions within 20 seconds, Visually Safe finds the programs writing the most data that are not Windows or a trusted publisher, stops them, cuts their internet and quarantines them (switchable to warn-only). Build and cache folders (`bin`, `obj`, `.git`, `node_modules`, …) and your safe folders are ignored. "Test it safely" runs a made-up ransomware in a throw-away folder.
- **Web blocklist**: blocks known malware and phishing websites for every program by pointing them at 0.0.0.0 in the Windows hosts file (free lists from URLhaus and Phishing Army, refreshed daily, at most 40,000 sites; Microsoft, Google, GitHub and similar are never blocked). Needs administrator rights, keeps a backup (`hosts.original.bak`), only touches its own marked block, has custom Block / Allow and a "Check a domain" box. Off by default: switch it on in Shields. It can't stop a browser that uses its own encrypted DNS.
- **Malware fingerprint feed**: with your free abuse.ch key (Settings) Visually Safe pulls the newest MalwareBazaar fingerprints every 12 hours into its block list. (abuse.ch's keyless downloads were switched off, so the key is required.)
- **Self-protection**: warns if Visually Safe's program file (same version, different fingerprint) or its settings file are changed behind its back (and puts the protection setting back), restarts Visually Safe within 2 minutes if something kills it (scheduled task "VisuallySafe Watchdog"; not after you use Exit), and optionally stops ordinary programs from ending or injecting into it.
- `tools\release.ps1` builds and zips a release (and signs it if you pass a code-signing certificate thumbprint); `tools\install.ps1` installs it to Program Files with a Start menu shortcut and start-at-logon. Real trust from Windows needs a certificate from a trusted authority, which Visually Safe can't make for itself.
- Developer check: `VisuallySafe.exe --shield-test result.txt` runs the ransomware simulation and the list and feed parsers.

## 1.0.32
- Rest the mouse on a Desktop or Explorer icon that Visually Safe already scanned and its result badge (green tick, yellow warning or red cross in a coloured box) shows again, for as long as you choose after the scan: 12 hours, 24 hours, 48 hours (default), 7 days, never, or off. Set it on the Settings page, next to the quarantine option.
