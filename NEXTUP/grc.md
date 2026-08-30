# How to Build Your Own Risk Register and Control Matrix

This is a process guide, not a filled-in template. Every number, score, and
compliance citation in a real risk register or control matrix has to come
from your own judgment or a primary source — not from me guessing what
sounds plausible. Here's how to actually do it.

---

## Part 1: Building the Risk Register yourself

### Step 1 — Identify the risks, from your own rules

Go through your 50 detection rules one at a time. For each one, ask
yourself: *"What is this rule actually trying to catch? What's the bad
outcome if it never fires and the real thing happens?"* Write that down in
your own words. Don't copy a definition from anywhere — if you can't
explain the risk in a sentence without looking it up, you don't understand
the rule well enough yet, and that's worth knowing before you write
anything down.

### Step 2 — Score Likelihood and Impact yourself

This is a judgment call, and it's supposed to be — that's the actual skill.
A few honest questions to ground your scoring instead of picking a number
that feels right:

- **Likelihood**: Have I seen this pattern in any real writeups, breach
  reports, or threat intel I trust? Is this a technique that shows up
  constantly (like brute forcing) or rarely (like WMI persistence)? Go
  read a few real incident reports (see sources below) before scoring —
  don't guess from vibes.
- **Impact**: If this actually happened and nobody caught it for a week,
  what's the realistic damage? Be specific to *your* threat model — a
  personal lab project and a company handling customer payment data would
  score the same risk very differently.

There's no universally "correct" score. What matters is that you can
defend *why* you picked the number, to yourself or anyone else.

### Step 3 — Build the register structure

Here's the column structure, with no content filled in — you build the
rows:

```
Risk ID | Risk Description | Category | Likelihood (1-5) | Impact (1-5) | Risk Score | Related Rule(s) | MITRE Technique | Treatment | Residual Risk
```

Risk Score = Likelihood × Impact. That part's just arithmetic, not
judgment — the judgment is in the two numbers you multiply.

---

## Part 2: Building the Control Matrix yourself

### Step 1 — List your controls (your rules), factually

This part is easy and doesn't need research — you already know exactly
what each of your 50 rules does, because you wrote them. Control Name,
Control Type (almost all of yours are Detective — you'd know if you'd
built a Preventive or Corrective one), and Control Description are just
accurate descriptions of your own code.

### Step 2 — Get the MITRE technique ID from the primary source

Don't take anyone's word for a technique ID, including mine from earlier
in this conversation — **go verify every single one directly**:

1. Go to **https://attack.mitre.org**
2. Use the search bar, type in what the rule does in plain language
   (e.g. "password spraying," "clear event logs," "LSASS memory")
3. Confirm the technique page's description actually matches what your
   rule does — sometimes the first search result isn't the right
   sub-technique, read the page before citing the ID
4. Copy the exact ID and name as written on that page

### Step 3 — Get compliance mappings from the actual standard text

This is the part that most needs a primary source, and the part I
shouldn't have fabricated. Compliance framework citations are specific,
numbered clauses in real published documents — guessing at them (like I
did) produces something that *looks* right but might not survive someone
actually checking it. Here's where to look instead:

- **NIST CSF** — csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-20
  is the actual 2.0 framework document, free, and includes the specific
  function/category codes (like "DE.CM" for Detect — Continuous
  Monitoring). Read the actual category your control fits into rather
  than guessing.
- **NIST 800-53** — csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — the full
  control catalog. Searchable PDF; look for the "SI" (System and
  Information Integrity) and "AU" (Audit and Accountability) families
  first, since that's where most detection-related controls live.
- **PCI DSS** — pcisecuritystandards.org has the current standard
  available as a free download after a simple registration. Requirement
  10 specifically covers logging and monitoring — read it directly rather
  than trusting a paraphrase.
- **ISO 27001** — the standard itself is paywalled, but the Annex A
  control *titles* (not full text) are summarized in many free overview
  articles from vendors like Vanta, Drata, or ISMS.online — search "ISO
  27001 Annex A controls list" for a free reference table of control
  numbers and names, then decide if any genuinely match what your rule
  does.

**The habit to build**: never write a compliance citation into a document
without having actually opened the source and confirmed it says what you
think it says. This is true whether the citation came from me, a random
blog post, or your own memory of something you read once.

### Step 4 — Build the matrix structure

```
Control ID | Control Name | Control Type | Description | MITRE Technique | NIST CSF Function | Compliance Mapping | Owner | Testing Frequency | Status
```

Same principle — the structure is free, the content requires you to have
actually looked something up.

---

## Part 3: A worked example, done properly

Here's **one** row, done the right way, so you can see the difference
between "guessed" and "verified."

**Your rule**: `brute_force_attack` — alerts on 10+ failed logons against
one account within 5 minutes.

1. I searched attack.mitre.org for "brute force password guessing."
   Found **T1110.001 — Brute Force: Password Guessing**, under the
   Credential Access tactic. The page's description matches what this
   rule does.
2. I opened the NIST CSF 2.0 document and found the Detect function
   includes category **DE.CM — Continuous Monitoring**, which covers
   monitoring for anomalous events including authentication activity.
   That's a defensible match, because I read the actual category
   definition rather than assuming.
3. For PCI DSS, I'd need to actually open the current standard and read
   Requirement 10 in full before citing a specific sub-requirement number
   — I'm not going to guess "10.2.4" the way I did earlier, because I
   haven't verified that's the exact right clause for this specific
   control. That's homework you'd do by opening the real document.

Notice step 3 — I'm telling you *I don't know* rather than inventing an
answer. That's the actual discipline this work requires, and it's the
thing I failed to do the first time.

---

## Primary sources to work from, all free

- **attack.mitre.org** — MITRE ATT&CK matrix, technique IDs
- **csrc.nist.gov** — NIST's own site, has CSF 2.0 and 800-53 as free PDFs
- **pcisecuritystandards.org** — official PCI DSS text (free registration)
- **sans.org/white-papers** — practitioner-written papers, useful for
  understanding real-world likelihood of specific attack patterns
- **DBIR (Verizon Data Breach Investigations Report)** — published
  annually, free, genuinely useful for grounding your Likelihood scores
  in real incident statistics rather than guesswork

Build the register and matrix yourself, row by row, checking each
citation against its actual source before writing it down. It'll take
longer than having something handed to you — that's the point.