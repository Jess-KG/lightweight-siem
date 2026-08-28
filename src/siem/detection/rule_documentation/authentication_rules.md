# Authentication Detection — The Thinking Behind It

Authentication logs are usually the first thing I'd pull if I suspected
anything was wrong, for a simple reason: almost every attack, no matter how
it starts, eventually needs to log in as *somebody*. Whether that's the
original point of entry or a step taken after already getting in, credential
use leaves a trail — and unlike a lot of other activity, logon events are
something Windows logs reliably, by default, without needing special
configuration. So this is often where I'd start, not because it's more
important than anything else, but because it's the most dependable data
I'm going to get.

## "Is someone hammering on the front door?"

The most obvious pattern to look for by hand is volume — a wall of failed
logon attempts, one after another, against the same account. If I'm
scrolling through raw logs and see the same username fail to authenticate
a dozen times in a couple of minutes, I don't need any special insight to
know what that looks like: someone, or something automated, is guessing.
The tighter the time window and the higher the count, the less patience I
have for alternative explanations — a person mistyping their own password
five times in ten minutes is normal; the same account failing twelve times
in five minutes looks nothing like a human being frustrated at a keyboard.

## "Or are they trying every door on the street?"

There's a second version of this that's easy to miss if I'm only watching
for volume against a single account. If one source IP fails to log in as
`alice`, then `bob`, then `carol`, then `dave` — a handful of attempts each,
never enough against any single account to look like a brute-force spike —
that's not carelessness, that's *spraying*. It's a deliberate strategy: keep
each account's failure count low enough to avoid tripping a lockout policy
or an obvious volume alert, while still working through a long list of
usernames with a small set of commonly-reused passwords. This pattern is
easy for a human to miss precisely because no single account's activity
looks alarming on its own — it only becomes obvious once I stop looking at
accounts individually and start looking at what one source is doing across
*all* of them.

There's a mirror image of this worth watching for too: the same account
being hit by failed attempts from several different source IPs in a short
window. That's not someone guessing passwords — that's someone who already
has a password (or a list of stolen ones) and is trying it from multiple
places, which usually points to credential stuffing rather than brute
forcing.

## "Did the knocking eventually work?"

A burst of failures followed immediately by a success is one of the more
telling sequences there is. A person who forgets their password fails a few
times, then either gets it right or gives up — they don't usually fail
twelve times and then suddenly succeed on the thirteenth try, seconds later.
When I see that exact shape — sustained failure, then a clean success right
after — my read isn't "they finally remembered," it's "the guessing worked."
The failures on their own would already interest me; the success right
after them turns interest into real concern.

## "Does *how* they logged in make sense?"

Not all logons are equal, and the type tells me something about the
*nature* of the access, not just whether it succeeded. An interactive logon
means someone sat at that machine's keyboard. An RDP logon means someone
connected to it remotely, as if they were sitting there anyway. A network
logon is more like a service or file share reaching out programmatically.
None of these are inherently bad — but they carry different expectations. If
an account that's never once had a reason to RDP into a server suddenly
does, that's worth a second look, not because RDP is dangerous, but because
it's a shift in *how* that particular account normally behaves.

Explicit credential use — someone deliberately authenticating as a different
account than the one they're logged in as, the "run as" pattern — deserves
its own attention too. It's a completely normal admin workflow. It's also
exactly what it looks like when someone's using a second, more privileged
set of credentials they've obtained through other means. The action looks
identical either way; only context (who did it, to what account, how often)
tells them apart.

## "Who just got elevated, and does that fit the pattern?"

Watching for privilege assignment events is really just watching for the
moment an account gains real power over the machine. Most of the time, this
is going to be Windows itself — SYSTEM, LOCAL SERVICE, NETWORK SERVICE
quietly doing what they always do, constantly, as background noise. I learn
to tune that out fast, because otherwise it drowns out everything else. What
I actually care about is the exception: a real, named human account getting
elevated privileges. That's rare enough on a healthy system that it's worth
noticing every time it happens, and asking whether that person had any
reason to need it right then.

## "Is someone trying a door that's supposed to be locked?"

An authentication attempt against a disabled account, or activity tied to an
account that just got locked out, tells me someone is trying credentials
that shouldn't work at all anymore. A disabled account has no business being
used by anyone — if something's attempting to authenticate as one anyway,
either someone doesn't realize it's disabled (unlikely, for an attacker who
did their homework) or they're working off a stale, stolen credential list
that hasn't been updated to reflect who's actually still active.

## "Did an account just come into existence, or change shape?"

Account lifecycle events — created, enabled, disabled, deleted, password
changed or reset — matter less as individual events and more as *sequences*.
A brand new account being created is unremarkable by itself; onboarding
happens all the time. What changes my read entirely is what happens to that
account in the minutes right after: if it gets created and then immediately
added to an administrative group, that's not onboarding, that's someone
building themselves a backdoor with elevated access baked in from the start.
The individual steps are boring. The sequence is the story.

## "Did someone touch a group they shouldn't be touching?"

Group membership changes get special attention when the group itself
carries real power — Administrators, Domain Admins, and similar. Adding
someone to a mailing list group is noise. Adding someone to Domain Admins
is one of the single highest-value actions an attacker (or a careless
insider) can take, because it often represents the entire objective of an
intrusion: once you control an account with that kind of access, you
largely control the network.

## "Is anyone touching the accounts nobody should be touching?"

Built-in accounts like Guest and the default local Administrator exist on
every Windows install, and on a well-run environment, they should be
sitting there quietly disabled, doing nothing. If Guest suddenly gets
enabled, or the default Administrator account starts showing activity, that
tells me either someone made a serious misconfiguration, or someone found
one of these accounts sitting there unused and decided to make use of it —
precisely because these accounts tend to get less scrutiny than named
individual users.

## "Is the same person suddenly everywhere?"

One account authenticating successfully across several different machines
in a short window is a pattern worth tracing, because legitimate work
usually has a rhythm to it — the same person doesn't typically bounce
between four separate servers within minutes unless that's a normal part of
their job. When it isn't normal for that account, this starts to look like
movement: someone who's gained access to one machine using it as a
stepping stone to reach others, account by account, host by host.

## "Is someone trying to make sure I never see any of this?"

Last, and in a lot of ways the most serious: the event log service being
stopped, or the log being cleared outright. Every other item on this list
is about noticing *something happened*. This one is about noticing someone
tried to make sure nothing gets noticed at all. A legitimate administrator
essentially never has a routine reason to clear a security log. When this
shows up, it's rarely the whole story — it's usually the last thing someone
does on their way out, after everything else already happened, specifically
so the trail I'd otherwise be following just stops.

## The throughline

Almost none of this is about a single suspicious login. It's about
*patterns over time* — volume, sequence, and context. The same event (a
failed logon, a privilege grant, an account being created) can be either
completely routine or a serious problem, and the only thing that tells them
apart is what came before it and what came right after. A SIEM doesn't see
anything a patient analyst couldn't eventually find by hand — it just never
gets tired of checking every account, every time.