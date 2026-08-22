# Interactive Cloud Security Logic Models

This repo has small Go programs I built to learn how basic security
works. Each folder is one small project. Each one focuses on one idea.

I wanted to write the logic myself, not just read about it. I am still
a beginner. But every program here does something real when you run it.

---

## What is inside

- **auth log scanner** > Reads a list of system logs and checks each one for failed logins. If the same IP fails 5 times within a few minutes, it gets flagged as suspicious. At 7 times, it gets blocked. Every threat gets saved into a small SQLite database, which also cleans up old records automatically so it doesn't grow forever.
- **buffer size guard** > Checks if user input is too big before
  letting it in. This stops input from going past the limit it should
  have.
- **cloud site checker** > Checks if a website is up or down.
- **data encryptor** > Takes user input and hides the private parts of
  it before saving it as a log. This way secrets do not sit in plain
  text.
- **ip blacklist filter** > Checks incoming traffic against a list of
  blocked IPs. If it matches, it blocks that traffic.
- **kubernetes access simulation** > A small copy of how role based
  access works. Different users get different levels of access, like
  in real Kubernetes systems.
- **port firewall** > Reads network connection logs. If an IP hits a dangerous port repeatedly within a 2-minute window, it gets put on a watch list at 2 attempts and fully blocked at 4. It also catches port scanning, when an IP tries several different ports quickly. Everything gets saved into an SQLite database too.
---

## How this relates to cybersecurity

Each program here stops a real kind of attack that hackers aactually
use. Here is how each one connects:

- **auth log scanner** > Hackers often try many passwords quickly on the same account, called a brute-force attack. My program checks if several failed logins happen from the same IP in a short time window, so it can tell the difference between a real attack and someone who just mistyped their password once.
  
- **buffer size guard** > Hackers sometimes send input that is much
  bigger than a program expects, on purpose. If the program does not
  check the size first, that extra data can spill into memory it
  should not touch. This can crash the program, or in bad cases let
  the hacker run their own code. This is called a buffer overflow. My
  program checks the size of input before accepting it, so this cannot
  happen.

- **cloud site checker** > Hackers can try to overload a website so it
  stops working for everyone else. This is called a denial of service
  attack. Even without an attack, a site can go down on its own. My
  program checks if a site is working, so a problem gets caught fast.

- **data encryptor** > If a hacker gets access to a log file, they may
  find passwords or private data sitting there in plain text. My
  program hides the private part of the data before it is saved as a
  log, so even if someone reads the log, the real secret stays hidden.

- **ip blacklist filter** > Hackers often attack from the same known
  IP address again and again, or use IP addresses already known to be
  harmful. My program checks incoming traffic against a list of blocked
  IPs, and stops the ones that match before they can do anything.

- **kubernetes access simulation** > If a hacker breaks into one small
  part of a system, they often try to move around and reach parts they
  should not have access to. This is called privilege escalation. My
  program makes sure each user only has the exact access they are
  allowed to have, so even if one part is broken into, the damage stays
  limited.

- **port firewall** > Before attacking a system, hackers usually scan it first to find open ports, like checking which doors are unlocked. My program watches for an IP hitting dangerous ports repeatedly, or trying many different ports quickly, and reacts before it becomes a real problem.
  
  ---

## Status

I am currently building sandbox demos for these programs using Meshery
Playground. I will upload them here over the next few days.

---
```bash
>  **Note:** Honestly, I didn't know that Go has such strict rules for curly brackets `{`. Coming from a C and C++ background,
 I am used to writing code in that format, so I didn't pay much attention to it at first and just wrote it that way. But when
 compiling, I got syntax errors, which led me to research and discover Go's strict styling rules. Over the next one or two
 days, I will be fixing the formatting across all my codes.

