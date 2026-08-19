# Interactive Cloud Security Logic Models

This repo has small Go programs I built to learn how basic security
works. Each folder is one small project. Each one focuses on one idea.

I wanted to write the logic myself, not just read about it. I am still
a beginner. But every program here does something real when you run it.

---

## What is inside

- **auth log scanner** > Reads a list of system logs. It finds lines
  that show a failed password. This helps spot someone trying to break
  in.
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
- **port firewall** > A simple firewall. It allows or blocks traffic
  based on rules I set.

---

## How this relates to cybersecurity

Each program here stops a real kind of attack that hackers aactually
use. Here is how each one connects:

- **auth log scanner** > Hackers often try many different passwords
  again and again on the same account. This is called a brute force
  attack. My program reads the logs and finds every time a password
  attempt failed, so this kind of attack does not go unnoticed.

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

- **port firewall** > Before attacking a system, hackers often scan it
  to find open ports, which are like open doors into the system. My
  program only allows traffic through ports that are approved, and
  blocks every other port, so there are fewer doors left open.

  ---

## Status

I am currently building sandbox demos for these programs using Meshery
Playground. I will upload them here over the next few days.
