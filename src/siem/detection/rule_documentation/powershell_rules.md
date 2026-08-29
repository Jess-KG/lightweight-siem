# PowerShell Detection — The Thinking Behind It

PowerShell is a strange thing to build detections around, because it isn't
malware — it's one of the most legitimate, widely-used tools on any Windows
machine. Admins live in it. So the mental model here isn't "PowerShell ran,
therefore something is wrong." It's closer to: PowerShell is powerful enough
that when it's used *the way an attacker would use it*, the signs are usually
visible if you know what to look for — even without a single line of malware
being involved, since PowerShell can do plenty of damage using only what's
already built into Windows.

## "Why would this command need to hide itself?"

The first thing that jumps out to me reading a raw command line is anything
built to avoid being read. `-EncodedCommand` takes a script, Base64-encodes
it, and hands it to PowerShell that way — which means if I'm looking at a
process list, I don't see the actual command being run, I see a wall of
gibberish. There's exactly one reason to do that: to stop someone like me
from immediately understanding what the command does. Legitimate scripts
occasionally use encoding for genuinely boring reasons — passing complex
strings safely across command-line boundaries — but the *ratio* of
legitimate-to-malicious use of this flag skews hard toward malicious in most
environments, which is why it earns a look every time.

`-WindowStyle Hidden` and `-NonInteractive` tell a similar story. A person
running PowerShell to actually get something done wants to *see* what it's
doing. The only reason to hide the window is so the person sitting at the
keyboard doesn't notice PowerShell just opened and did something. That's not
a technical necessity, it's a concealment choice.

## "Is this command trying to reach outside the network?"

`DownloadString`, `Invoke-WebRequest`, `Net.WebClient` — these are the
building blocks of a PowerShell script reaching out to the internet and
pulling something back. On their own they're completely ordinary — plenty of
legitimate automation downloads things. What makes me pay attention is
*combination*: a hidden, encoded PowerShell command that also reaches out to
download something is a very different story than an admin's visible,
readable script doing the same download as part of routine patching. Context
stacks; a single indicator rarely tells the whole story on its own.

Following through on that thought is why I don't stop at "did the command
line mention a download." I actually want to know: did this PowerShell
process, shortly after starting, make a real network connection anywhere?
That's a stronger, harder-to-fake signal than parsing text, because it's
observed *network behavior*, not just a string that happened to appear in a
command.

## "What did this PowerShell process actually spawn?"

If PowerShell turns around and launches `cmd.exe`, that's worth noticing —
not because it's rare in isolation, but because it's an extra hop in the
chain that doesn't usually serve a legitimate purpose. Most day-to-day
PowerShell use doesn't need to drop into `cmd.exe` at all; when it does, I
want to know what that `cmd.exe` process did next, because the chain is
usually building toward something.

## "Who launched PowerShell, and does that make sense?"

This is one of my favorite checks because it's cheap and surprisingly
effective: PowerShell being spawned by `explorer.exe` (someone opened it
themselves) or by `cmd.exe` (someone's already in a shell and opened another
one) is completely ordinary. PowerShell being spawned by `WINWORD.EXE`,
`EXCEL.EXE`, a browser, or some unrelated application entirely — that's a
parent process that has no everyday business launching a scripting engine.
The parent tells me *how* PowerShell came to exist, and "a document opened
it" is a categorically different, more alarming answer than "a person typed
`powershell` into a terminal."

## "Are there specific phrases that only show up in a certain kind of script?"

`IEX` (short for `Invoke-Expression`), `FromBase64String`,
`Reflection.Assembly` — these aren't inherently evil, but they cluster
heavily around a specific pattern: taking a blob of encoded or downloaded
text and executing it as code *in memory*, without ever writing a file to
disk. That's attractive to an attacker for the same reason it's suspicious to
me — nothing lands on the disk for antivirus to scan, and nothing shows up
in a file listing afterward. A script that goes out of its way to run purely
in memory is a script that's trying not to leave evidence behind.

## "What happened right after PowerShell ran?"

This is the part that turns a single suspicious event into a *story*. A
PowerShell process by itself, even an encoded, hidden one, is a moment in
time. But if that same process is followed — seconds later — by a registry
write into a Run key, that's not two coincidences, that's PowerShell doing
the thing it was launched to do: establish persistence, so it survives a
reboot. Same logic applies to a network connection appearing right after: the
PowerShell process didn't just sit there, it actually reached out and did
something with its access.

## "Is someone actively trying to make themselves harder to catch, going forward?"

Script Block Logging is a Windows feature that records what PowerShell
actually executes, specifically so people like me can go back and look. If I
see that setting getting disabled, that's not "unusual PowerShell activity"
in the normal sense at all — that's someone actively working to blind future
investigation. In a lot of ways, this is one of the most important signals
on the whole list, because it's evidence of premeditation: whoever did this
knew logging existed and specifically wanted it gone before doing whatever
comes next.

## The throughline

Almost nothing on this list is suspicious purely by itself — that's the
whole difficulty with PowerShell. What actually separates "an admin doing
their job" from "an attacker living off the land" is concealment (hidden,
encoded), unusual origin (wrong parent), and what happens *next*
(persistence, network activity, more processes). A SIEM's job here isn't to
flag PowerShell — it's to flag PowerShell behaving like it doesn't want to
be seen.