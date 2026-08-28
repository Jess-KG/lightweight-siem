# Command Shells & Scripting Detection — The Thinking Behind It

The tools in this category — `cmd.exe`, `wscript.exe`, `cscript.exe`,
`mshta.exe` — are what security people mean when they talk about "living off
the land." None of them are malware. All of them ship with every copy of
Windows ever installed. That's exactly what makes them useful to an
attacker: launching one of these doesn't require bringing in a single custom
file, which means there's nothing unusual sitting on disk for antivirus to
catch. If I'm thinking like someone trying to avoid detection, these are the
first tools I'd reach for — not because they're powerful, but because
they're *already trusted*.

## "Is this tool doing anything on its own, or is it just noise?"

`cmd.exe` running by itself, doing nothing else notable, is genuinely the
weakest signal on this entire list — it's one of the most commonly launched
programs on any Windows machine, full stop. I don't get excited about a bare
`cmd.exe` execution. What I actually care about is `cmd.exe` as a *stepping
stone* — what did it do, and what did it lead to. The other three engines
are individually rarer in day-to-day use, so they earn slightly more of my
attention on their own, but even then, the interesting part is almost never
"this ran," it's "this ran, and then—"

## "Did this thing launch from somewhere a normal program wouldn't?"

Same instinct as with any process: a script running out of `Temp` or
`AppData` is a script running from a folder that any user can write to
without special permission — no install, no admin approval, just drop a file
and run it. Legitimate software occasionally does live there, briefly, mid-
install. But a `.vbs` file quietly sitting in someone's Temp folder and
getting executed isn't how software installation normally looks.

## "What did this script actually launch next?"

This is where the real story starts. A script by itself is just an
interpreter running — what makes it interesting is what it *does*. If a
script spawns something like `certutil.exe` with unusual arguments, that's
worth knowing, because `certutil` — a tool meant for managing certificates —
has a well-known side ability to download files. Attackers use exactly this
kind of quiet repurposing: reach for a tool that's already trusted and
already installed, and use it for something it was never really meant to do.
Seeing a script kick off a tool like that isn't proof of anything by itself,
but it's the kind of chain I'd want to trace forward.

The same goes for a script spawning PowerShell. A `.vbs` or `.hta` file that,
the moment it runs, immediately hands off to PowerShell — that's a very
common two-stage pattern: the first-stage script exists purely to get
PowerShell running with a specific set of instructions, often because
PowerShell itself has capabilities the initial script doesn't. Seeing that
handoff happen is a strong "keep looking" signal.

## "Did this script try to make itself permanent?"

Every attacker eventually faces the same problem: the machine will get
rebooted, and unless something's been left behind to run again, whatever
foothold they had disappears. That's the entire purpose of persistence
mechanisms — Registry Run keys, scheduled tasks, startup folder entries.
If I see a script run, and moments later a Run key gets written, I don't
need to guess what happened — the story writes itself. The gap between "the
script did something" and "that something turned out to be planting a
registry entry" is often measured in single-digit seconds, because there's
no reason to wait once you've already got code execution.

## "Did this lead somewhere I should really be worried about?"

Two outcomes on this list are, to me, categorically more serious than
everything else here, because of what they represent rather than what they
technically are.

The first is a script's process reaching into `lsass.exe` — the process that
holds logged-in users' credentials in memory. There's essentially no everyday
reason for a script to touch that process at all. When I see it, I'm no
longer thinking "suspicious," I'm thinking "someone is actively trying to
steal passwords off this machine, right now."

The second is timing-based rather than behavior-based: the same person who
just ran a script on one machine, logging into an *entirely different*
machine shortly after. On its own, a person logging into a second computer
means nothing — that's just normal work. But paired with "they just ran a
script minutes earlier," it starts to look like movement: whatever that
script did — grabbed credentials, opened a connection, set something up — is
now being used to reach further into the network. This is the one item on
the list that isn't really about the script at all; it's about noticing that
*after* the script, the same person showed up somewhere new.

## The throughline

None of these four tools are the problem. `cmd.exe`, `wscript.exe`,
`cscript.exe`, and `mshta.exe` exist on every Windows install for entirely
legitimate reasons, and flagging their mere existence would drown me in
noise within an hour. What actually matters is *sequence* — what launched
the script, where it launched from, what it launched next, and what changed
on the machine (or on the network) in the minutes right after. A script
running is a sentence with no punctuation; it's the next thing that happens
that tells me whether it ends in a period or an exclamation mark.