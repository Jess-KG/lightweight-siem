# Process Detection — The Thinking Behind It

If I didn't have a SIEM and had to manually pull process creation logs off a
box I was worried about, here's the mental checklist I'd actually be running
through, and why.

## "Where did this thing launch from?"

The very first thing I look at with any unfamiliar process isn't its name —
it's its *path*. A file called `svchost.exe` means nothing on its own; the
name is free, anyone can call anything whatever they want. What Windows
actually enforces is much narrower: legitimate system binaries live in very
predictable places. `svchost.exe`, `services.exe`, `lsass.exe` — if these
aren't in `C:\Windows\System32\`, something is impersonating a trusted name
to blend in, hoping I glance at the process list and see a name I recognize
without checking where it's actually running from. This is such a cheap trick
for an attacker to pull, and such a cheap check for me to run, that it's
always my first move.

The same instinct extends outward: `Temp`, `AppData\Local`, `AppData\Roaming`,
`Users\Public` — these are folders *any logged-in user* can write to without
needing admin rights. Legitimate software occasionally runs from there too
(installers, updaters), so a hit alone isn't proof of anything. But it's the
kind of thing that makes me lean in and look at what else is going on with
that process, rather than dismiss it.

## "Who launched who?"

Process trees are where the real story lives. A single process in isolation
rarely tells me much — it's the *relationship* between parent and child that
gives it away. If I open a raw process list and see `WINWORD.EXE` as the
parent of `cmd.exe`, I don't need any other context to get suspicious. Word
documents don't open command prompts. Neither do Excel spreadsheets open
PowerShell, and neither does Outlook. The only time this happens is a macro,
and the only reason a macro spawns a shell is to run code the document
itself couldn't run on its own. This is one of the oldest, most well-known
attack patterns there is, and it's *still* effective, because it exploits
something ordinary: someone just opened an email attachment.

The same logic works in reverse, on the system side. Windows' own core
processes boot up in a strict, predictable order — `smss.exe` starts
`csrss.exe` and `wininit.exe`; `wininit.exe` starts `services.exe`;
`services.exe` starts `svchost.exe` instances. This chain barely ever
changes on a healthy system. If I see `smss.exe` spawn something like
`notepad.exe`, that's not "unusual" in some vague sense — it's a process
doing something it has *never once* had a legitimate reason to do, on any
Windows machine, ever. That's a much stronger signal than most suspicious
activity gets to be.

## "What is this process actually being told to do?"

The command line is where intent shows up. A process name tells me *what*
ran; the command line tells me *why*. Flags like `-EncodedCommand` or
`-WindowStyle Hidden` aren't things a person types when they're just trying
to get work done — they exist specifically to avoid being watched or
understood by someone glancing at a running process. Nobody encodes a
PowerShell command because it's convenient; they encode it because they
don't want the plaintext command sitting there in plain view.

## "Who's running this, and as what?"

Context about the *account* matters as much as the process itself. If SYSTEM
— the most privileged account on the box — is executing something that isn't
one of the known handful of Windows core processes, that's worth a hard look.
SYSTEM doesn't casually run arbitrary tools; when it does, it's usually
because something already has a serious foothold and is using SYSTEM's
authority to do things a normal user account couldn't.

## "Did this file even exist five minutes ago?"

One of the more subtle things I watch for: a file gets created, and almost
immediately, that exact file gets executed. On a normal day, software
doesn't work like that — installers unpack files and register them, they
don't drop an .exe and fire it off within seconds. That tight time gap
between *creation* and *execution* is the signature of a dropper: something
already running on the box pulled down a second-stage payload and launched
it right away, before anyone had a chance to notice the file appear.

## "Where does this file actually live?"

Two more location checks round this out. A process running off a UNC path
(`\\server\share\...`) means the executable never touched the local disk at
all — it's running directly off a network share, which is both unusual for
everyday software and a known technique for staying off endpoint file scans.
And a process running from anything other than the `C:` drive is worth a
glance, though I hold this one loosely — it's genuinely weak on its own,
since plenty of legitimate setups use a `D:` drive for something mundane. I
treat it as a tiebreaker, not a verdict.

## The throughline

None of these checks, alone, proves anything. What they share is that each
one answers a question a careful analyst asks by *habit*: where did this come
from, who's its parent, what's it being told to do, who's running it, and how
did it get here. A SIEM doesn't replace that thinking — it just runs the same
questions across thousands of events a second instead of one at a time by
hand.