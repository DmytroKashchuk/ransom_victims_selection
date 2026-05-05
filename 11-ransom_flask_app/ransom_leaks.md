# Ransomware Groups — Internal Leaks
- https://github.com/NorthwaveSecurity/complete_translation_leaked_chats_conti_ransomware
- https://github.com/D4RK-R4BB1T/BlackBasta-Chats/

 
| Group | Leak date | Content | Download link |
|---|---|---|---|
| **Conti** | Feb 27, 2022 | ~170k Jabber messages (2020–2022), Rocket.Chat logs, source code, internal docs | [github.com/TheParmak/conti-leaks-englished](https://github.com/TheParmak/conti-leaks-englished) <br> Original mirror: [share.vx-underground.org/Conti/](https://share.vx-underground.org/Conti/) <br> EN translations (CSV): [github.com/NorthwaveSecurity/complete_translation_leaked_chats_conti_ransomware](https://github.com/NorthwaveSecurity/complete_translation_leaked_chats_conti_ransomware) |
| **Black Basta** | Feb 11, 2025 | ~196k Matrix/Element messages (Sep 18, 2023 – Sep 28, 2024), `bestflowers.json` ~50 MB | [github.com/0xCh1/BlackBasta](https://github.com/0xCh1/BlackBasta) <br> EN translation + notebooks: [github.com/fr0gger/jupyter-collection/tree/main/bb_leak_tr](https://github.com/fr0gger/jupyter-collection/tree/main/bb_leak_tr) |
| **Everest** | Apr 5–7, 2025 | DLS defacement only — no internal DB or chats released | No public dataset available (see note below) |
| **LockBit (4.0 — LightPanel)** | May 7, 2025 (dump dated Apr 29, 2025) | MySQL dump, 20 tables: ~60k BTC addresses, 4,442 negotiation messages, 75 affiliates with plaintext passwords, build configs | [github.com/Hexastrike/LockBit-Database-Leak-2025](https://github.com/Hexastrike/LockBit-Database-Leak-2025) <br> Mirror: [github.com/heptaliftdev/lockbit-database-leak-2025](https://github.com/heptaliftdev/lockbit-database-leak-2025) |
 
## Why there is no Everest database
 
This is a legitimate question — the Everest case is architecturally different from the others.
 
**What actually happened**: Everest's Tor-based Data Leak Site (DLS) was defaced on the weekend of April 5–6, 2025 with the same "Don't do crime CRIME IS BAD xoxo from Prague" message later seen on LockBit. The site went fully offline on April 7. The attack vector was likely a WordPress vulnerability — Flare researchers noted the DLS was built on a WordPress template.
 
**Why no data came out**:
 
1. **The DLS is not the backend.** Everest's leak site is a *publication* surface — the public-facing catalogue of victims and samples. The operational infrastructure (negotiation chats, affiliate panel, builder, internal comms) runs on separate servers and was not touched. Compare with LockBit, where the attacker got into the actual affiliate admin panel (MySQL backend), and Black Basta, where the attacker got into the Matrix server with the chat history.
2. **Different architecture.** Everest has never run a RaaS affiliate panel comparable to LockBit's. It operates more as a hybrid ransomware + Initial Access Broker shop, with insider recruitment since late 2023. There is no centralized chat DB equivalent to Black Basta's Matrix server, nor a structured affiliate panel DB.
3. **The attacker's goal was disruption, not exfiltration.** The defacement was purely symbolic — a taunt, possibly by DragonForce during its 2025 expansion campaign (they absorbed BlackLock around the same time and claimed RansomHub's infrastructure shortly after). No data dump was published on any forum or paste site.
4. **Everest rebuilt and resumed.** By mid-2025 the group was back online, and by late 2025 they were claiming high-profile attacks (Heathrow/Brussels/Berlin airport systems, Swedish grid). If internal data had been exfiltrated, the fallout would have been visible.
So for academic purposes Everest sits in a separate category: **defacement without data disclosure**. You can cite the event (TechCrunch, The Record, Flare all covered it) but there is no dataset to analyze.
 
## General notes
 
- **Conti**: the original dump was on AnonFiles (`1.tgz`, 14 MB), now offline. The GitHub mirrors are the most reliable source.
- **Black Basta**: originally on MEGA, later taken down. Redistributed via Telegram (`@shopotbasta`). Main file is `bestflowers.json`.
- **LockBit**: the attacker posted the dump on LockBit's own onion sites after the defacement. Likely linked to the Everest defacement (same message, same suspected actor — possibly DragonForce).
- **Yanluowang** (Mar 2022) also had internal chats leaked on Twitter, but publicly available structured datasets are limited.