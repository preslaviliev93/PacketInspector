<div align="center">

# Packet Inspector

**See what your network is actually doing, explained in plain language.**

A desktop packet analyzer for Windows and Linux, inspired by Wireshark, but built for people who want answers rather than hex dumps.

[Features](#what-it-does) &nbsp;|&nbsp; [Getting started](#getting-started) &nbsp;|&nbsp; [Capturing traffic](#capturing-traffic) &nbsp;|&nbsp; [MikroTik](#capturing-from-a-mikrotik-router) &nbsp;|&nbsp; [Examples](#a-few-real-world-examples) &nbsp;|&nbsp; [Filters](#finding-things-the-display-filter)

</div>

---

## Why this exists

Wireshark is brilliant, and it is also a lot. You open a capture, get forty thousand rows of `TCP 443 → 51234 [ACK]`, and still have to work out why the video call keeps freezing.

Packet Inspector reads the same traffic and does the first round of thinking for you. It groups packets into connections, works out which names belong to which IP addresses, measures how long servers take to answer, and points out the things that deserve a closer look. Every conclusion links back to the packets it came from, so you can check the reasoning instead of taking it on faith.

## What it does

| | |
|---|---|
| **Live overview** | Throughput over the last two minutes, the protocol mix, who is talking the most, and which internet services your machines are reaching. Names come from DNS answers and TLS handshakes, so you see `docs.example.com`, not just `203.0.113.45`. |
| **Packets, explained** | Every packet comes with a short explanation of what it is doing, the fully decoded layers, and the raw bytes. Click a field and its bytes light up. |
| **Connections** | Every connection with its state, round-trip time, retransmissions and resets. Open one to get a sequence diagram of the whole exchange: handshake, data, errors and goodbye. Quick filters narrow the list to TCP, UDP, databases, problems or alerts. |
| **Alerts with evidence** | Port scans, ARP spoofing, passwords sent unencrypted, backdoor ports, DNS tunneling, malware-style "check-ins", rogue DHCP servers, outdated TLS, large uploads and more. Every alert explains itself, suggests what to do, and can be saved as its own capture file. |
| **Troubleshooting** | Automatic checks for packet loss, latency, slow or failing DNS, refused connections and unreachable hosts, with the connections responsible. |
| **Databases** *(Expert)* | Every MySQL/MariaDB, PostgreSQL, SQL Server, MongoDB, Redis and Oracle server and session in the traffic: version, who logged in, which database, whether it was encrypted, failed logins and the queries that ran. Alerts for unencrypted logins, password guessing, databases exposed to the internet and injection-style SQL. |
| **Watchlist** *(Expert)* | Your own rules: get an alert whenever traffic involves a particular IP address, a whole network, a host name (and its sub-domains) or a port. |
| **Files in, files out** | Import `.pcap`, `.pcapng` and gzipped captures from tcpdump, Wireshark or a MikroTik router. Save as `.pcapng` and export packets, connections or alerts to CSV. |
| **Simple and Expert mode** | Expert (the default) shows everything. Flip the switch in the top-right corner to **Simple** and the packet-level views, protocol charts and capture filters step aside, the wording becomes everyday language ("Needs attention" instead of "High", "Data sent twice" instead of "TCP retransmissions"), and every connection gets a one-word verdict such as *OK*, *Refused* or *Unreliable*. The app remembers your choice. |
| **Demo mode** | A simulated home network with a handful of incidents baked in. Useful for a first look, for teaching, and for trying things without admin rights. |

## Getting started

You need [Node.js](https://nodejs.org) 20 or newer.

```bash
git clone <your-repo-url> packet-inspector
cd packet-inspector
npm install
npm start
```

When the window opens, click **Demo**. Within a minute or so you will see a port scan, a password sent over plain HTTP, an ARP spoofing attempt and a few other things show up under **Alerts**. Click any of them, then **Show evidence**, and you land on the exact packets involved.

Other useful commands:

```bash
npm test            # decoders, file formats, MikroTik stream, detectors, end to end
npm run typecheck   # TypeScript checks only
npm run icons       # regenerate the app icons after editing build/icon.svg
```

## Installing it like a normal app

`npm start` is handy while developing, but for everyday use build a proper package. It gets the Packet Inspector icon, a Start menu or app launcher entry, and does not need Node.js on the machine.

### Windows

```bash
npm run dist:win
```

When the build finishes, everything you need sits right in the project folder, each with its own icon:

| File | Icon | What it does |
|---|---|---|
| `Packet Inspector.exe` | the app | Opens Packet Inspector. If it isn't installed yet, it offers to run the installer next to it. |
| `Install Packet Inspector.exe` | app with a green arrow | The installer. It lets you choose who it's for and where it goes, and adds a desktop and Start menu shortcut. |
| `Uninstall Packet Inspector.exe` | app with a red minus | Finds the installed copy, wherever and however it was installed, asks you to confirm, and starts its uninstaller. |

The installer checks first whether Packet Inspector is already on the computer, so you never end up with a second copy by accident:

| Already installed | What the installer offers |
|---|---|
| Nothing | A normal install |
| The same version | **Uninstall** it, or close |
| An older version | **Update** it (your settings are kept), **uninstall** it, or close |
| A newer version | **Uninstall** it, or close |

Silent installs (`/S`) skip that question and simply update, so scripted deployments keep working.

`release/` also holds a portable build, `PacketInspector-1.0.4-portable.exe`, a single file that runs without installing. It's good for a USB stick or a machine you don't own.

**Uninstalling.** Double-click `Uninstall Packet Inspector.exe`, run the installer again and choose uninstall, pick **Uninstall Packet Inspector** in the Start menu, or use Settings > Apps. Each removes the app, its shortcuts and its saved settings completely. The portable `.exe` installs nothing, so to get rid of it, delete the file.

The executables are not code-signed, so the first time you run one, Windows SmartScreen may say it "protected your PC". Click **More info**, then **Run anyway**.

If the build stops with `Cannot create symbolic link: A required privilege is not held by the client`, electron-builder is failing to unpack its signing tools. Turn on **Developer Mode** (Settings > System > For developers) once, or run the build from an Administrator terminal, and try again.

### Linux

```bash
npm run dist:linux
```

You get an AppImage and a `.deb` in `release/`:

```bash
# AppImage: runs anywhere, no install
chmod +x "release/Packet Inspector-1.0.4.AppImage"
"./release/Packet Inspector-1.0.4.AppImage"

# .deb: installs into the applications menu (Debian, Ubuntu, Mint, Pop!_OS)
sudo apt install ./release/packet-inspector_1.0.4_amd64.deb
```

Build each platform's package on that platform (or in CI).

## Capturing traffic

When the app opens, the **Overview** tab lists every network adapter on the machine: Ethernet, Wi-Fi, VPN tunnels and so on, each with its IP and MAC address. Click one and capture starts. The same list is in the toolbar dropdown, next to the MikroTik stream option, if you prefer that.

### Windows: nothing to install

Packet Inspector captures with a facility built into Windows itself, so you don't need Wireshark, Npcap or anything else. When you press **Start**, Windows asks once for administrator permission (the usual "Do you want to allow this app to make changes" prompt). Say yes and packets start flowing.

Two things to know about this built-in mode:

- It sees all IP traffic: web, DNS, TLS, QUIC, ping, file sharing and so on. It does not see Ethernet-level frames such as ARP, so the ARP spoofing detector stays quiet.
- Capture filters (the BPF box) are not available. Use the display filter on the Packets tab instead.

If you want full Ethernet-level capture and no permission prompt, install the free [Npcap driver](https://npcap.com/#download) together with dumpcap (the simplest way to get both is [Wireshark](https://www.wireshark.org/download.html)), then click **check again**. Packet Inspector notices and switches over automatically. This is entirely optional.

### Linux: handled by the package

The `.deb` package depends on `tcpdump`, so `apt` installs it for you. When you start a capture, the app asks for your password through the standard system dialog (`pkexec`), because reading raw traffic needs root.

If you would rather not type a password every time, let your user capture directly:

```bash
# Debian / Ubuntu - answer "Yes" when asked whether non-superusers may capture
sudo apt install tshark
sudo usermod -aG wireshark $USER

# Fedora
sudo dnf install wireshark-cli
sudo usermod -aG wireshark $USER
```

Log out and back in so the group change takes effect. With the AppImage, install `tcpdump` (or the above) yourself, since AppImages can't pull in system packages.

### Capture filter

With Npcap/dumpcap on Windows, or on Linux, the box next to the interface list takes a standard BPF filter, the same syntax tcpdump uses. It is applied before packets reach the app, so it is the right tool for keeping a busy link manageable.

```text
not port 22                     skip your own SSH session
host 192.168.1.50               only one machine
port 53 or port 443             DNS and HTTPS only
net 10.0.0.0/8 and not arp      the office network, without the ARP noise
```

## Capturing from a MikroTik router

There are two ways to get traffic out of a MikroTik, and Packet Inspector handles both.

### Option 1: stream it live

The router sends every captured packet to your computer as it happens, using the TZSP protocol on UDP port 37008. Choose **MikroTik sniffer stream (TZSP, UDP 37008)** from the interface list and press **Start**. Then, on the router:

```routeros
/tool sniffer set streaming-enabled=yes streaming-server=192.168.88.10 filter-stream=yes
/tool sniffer set filter-interface=ether1
/tool sniffer start
```

Replace `192.168.88.10` with your computer's address. When you are done:

```routeros
/tool sniffer stop
```

The packets arrive wrapped in TZSP headers, and Packet Inspector unwraps them, so you see the router's real traffic rather than thousands of identical UDP packets. Filtering happens on the router side, for example `/tool sniffer set filter-ip-address=192.168.88.20/32 filter-port=443`.

**If nothing shows up**, the usual reason is Windows Firewall. On a network Windows treats as "Public", it silently drops the router's packets unless a rule allows incoming UDP 37008. When that rule is missing, Packet Inspector says so in a banner with an **Allow through firewall** button that adds it (Windows asks for permission once). Installing Packet Inspector for everyone on the computer adds the rule automatically.

If still nothing arrives after 10 seconds, the app shows a checklist: the exact `streaming-server` address to set on the router (this computer's real network address, not a virtual one), the firewall rule, VPN "kill switch" settings, and the sniffer's own filters.

You don't need to filter on port 37008 to find the stream. Packet Inspector unwraps it, so the list shows the router's real traffic. When a stream turns up inside a normal capture, its packets are marked **From MikroTik stream**.

### Option 2: save a file and import it

```routeros
/tool sniffer set file-name=sniff.pcap file-limit=10000KiB
/tool sniffer start
# ...wait a while...
/tool sniffer stop
```

Download `sniff.pcap` from **Files** in WinBox or WebFig (or with `scp admin@192.168.88.1:sniff.pcap .`), then click **Import** in Packet Inspector, or just drag the file onto the window.

## Importing captures from elsewhere

**Import** (or dragging a file onto the window) accepts:

- `.pcap` and `.pcapng`, including nanosecond timestamps
- gzipped captures such as `capture.pcap.gz`
- Ethernet, Linux "cooked" captures (`tcpdump -i any`), loopback and raw IP link types
- tcpdump captures of a MikroTik TZSP stream, which are unwrapped automatically

A typical way to grab traffic from a Linux server you can only reach over SSH:

```bash
# on the server: capture 2 minutes of web traffic, compressed
sudo timeout 120 tcpdump -i any -w - 'port 80 or port 443' | gzip > web.pcap.gz

# on your machine
scp server:web.pcap.gz .
```

Then drop `web.pcap.gz` onto Packet Inspector.

## A few real-world examples

**"The internet is slow."** Start a capture, use the network normally for a minute, and open **Troubleshoot**. If packet loss is high, look at Wi-Fi signal or cabling. If DNS lookups take 300 ms, your DNS server is the problem, not your connection. **Slowest servers to respond** tells you whether one far-away service is to blame or everything is.

**"Something on the network is acting strangely."** Leave a capture running and check **Alerts**. A device trying 20 different ports on your laptop in a few seconds is a port scan. A machine contacting the same server every 60 seconds like clockwork is worth identifying. Click **Show evidence** on any alert to see exactly what was observed.

**"Did that app really send my password in clear text?"** Filter the packets with `tag:credentials`. Packet Inspector detects logins over plain HTTP, FTP, POP3, IMAP and SMTP and raises a high-severity alert, while masking the secret itself in the decoded view.

**"Why does this one connection keep failing?"** Find it under **Connections** (search by name, IP or port) and open the sequence diagram. A `SYN` answered by an immediate `RST` means nothing is listening on that port, or a firewall said no. A `SYN` sent three times with no answer means packets are being silently dropped somewhere along the way.

**"What is this router actually forwarding?"** Stream the MikroTik sniffer to Packet Inspector, then look at **Top internet destinations** on the Overview. Everything there is clickable and takes you to the matching packets.

## Databases

The **Databases** tab (Expert mode) lists every database server seen in the capture and every session with it. Packet Inspector understands the login and query phase of:

| Database | Default port | What you get |
|---|---|---|
| MySQL / MariaDB | 3306 (or any port) | server version, user, database, every query, access-denied errors |
| PostgreSQL | 5432 (or any port) | server version, user, database, application name, queries, error codes |
| Microsoft SQL Server | 1433 | server version, whether encryption was negotiated, SQL login user, database, application, batches, login failures |
| MongoDB | 27017 | database and command (find, insert, aggregate...), authentication failures |
| Redis | 6379 | commands, `AUTH` (password hidden), wrong-password errors |
| Oracle | 1521 | service name, client program and OS user, ORA- errors |

Once a session switches to TLS, its contents can't be read any more, and the tab says so. That is the outcome you want.

These situations raise alerts:

- **Unencrypted database login**, with the exact setting to change for that database.
- **Failed logins**, and **repeated failed logins** from one client (password guessing).
- **A database reachable from the internet**, or **database traffic leaving your network**.
- **A database password in clear text** (Redis `AUTH`, PostgreSQL cleartext authentication, SQL Server logins without encryption).
- **Suspicious commands**: `UNION SELECT`, `OR 1=1`, `xp_cmdshell`, `INTO OUTFILE`, `COPY ... FROM PROGRAM`, deliberate `SLEEP()` delays, and Redis `CONFIG SET dir`.

## Watchlist

Sometimes you already know what you care about: one server, a partner's network, a domain, a port that should never be used. Add it on the **Watchlist** tab (Expert mode), and Packet Inspector raises an alert, at the severity you choose, the moment it shows up.

| Rule type | Example | Matches |
|---|---|---|
| IP address | `203.0.113.7` | any packet to or from that address |
| Network | `10.20.0.0/16`, `2001:db8::/32` | any packet to or from an address inside it |
| Host name | `example.com` | DNS lookups, TLS server names and HTTP hosts for it **and its sub-domains**, plus traffic to addresses that resolved to it |
| Port | `3389` | any TCP or UDP traffic on that port |

A few ways people use it:

```text
Network    10.20.0.0/16     "Payroll VLAN"      High     who is talking to payroll?
Host name  dropbox.com      "Personal cloud"    Medium   uploads to a service you don't allow
Port       3389             "Remote Desktop"    Medium   RDP anywhere on the network
IP address 203.0.113.7      "Old file server"   Low      is anything still using it?
```

Rules are saved and apply to new traffic from the moment you add them. Every alert links to the packets that matched, matching packets carry the `watch` tag, and the rule list counts its matches. You can also add a rule straight from a packet (**Watch** button in the details), a connection (**Watch server**) or the Databases tab.

## Finding things: filtering packets

The **Packets** tab has a filter bar that you click rather than type:

- **Search packets**: type anything (a name, an address, "login") to search the packet list.
- **+ Add filter**: choose what to filter by (host, sent by, sent to, network, port, protocol, database, marker or connection number), then pick a value. Suggestions come from your capture: hosts with their names, ports with their service names, protocols with packet counts.
- **Quick buttons**: **Problems**, **Alerts**, **DNS**, **Web** and **DB** switch on and off with one click.
- **Chips**: every active filter is a chip in plain words, such as "Host demo-laptop (192.168.1.23)" or "Not port 443 (HTTPS)". Click a chip's text to flip it between *only these* and *hide these*. Click × to remove it, or **Clear** to start over.

Clicking through from elsewhere in the app ("Show evidence", "Show packets", a host on the Overview) arrives as chips too, so you can always see why the list looks the way it does.

### Typing filters (optional)

If you prefer the keyboard, type a filter into the search box and press **Enter**; it turns into a chip. The same words work in links and exports:

| You type | You get |
|---|---|
| `example.com` | anything mentioning it: names, addresses, ports, protocol, info |
| `host:192.168.1.5` | packets to or from that address (or name) |
| `src:10.0.0.1` / `dst:10.0.0.1` | one direction only |
| `port:443` | either port |
| `net:10.20.0.0/16` | either address inside a network (IPv6 works too) |
| `db:` or `db:mysql` | every packet of a database session, or of one kind: `mysql`, `postgresql`, `mssql`, `mongodb`, `redis`, `oracle` (aliases such as `mariadb`, `postgres`, `sqlserver` work too) |
| `proto:dns,tls` | one or more protocols |
| `flow:12` | a single connection |
| `id:5,9,12` | specific packets (this is what **Show evidence** uses) |
| `tag:retransmission` | marked packets: `retransmission`, `rst`, `dup-ack`, `zero-window`, `syn`, `alert`, `credentials`, `dns-error`, `database`, `watch` |
| `is:problem` | anything that looks like trouble |
| `-proto:quic` | put a minus in front of any term to exclude it |

Terms are combined, so these work the way you would expect:

```text
host:192.168.1.23 proto:dns              DNS from one machine
port:443 is:problem                      HTTPS packets with loss or resets
-proto:quic -proto:mdns                  hide the two noisiest protocols
tag:dns-error                            every failed name lookup
db:postgresql -is:problem                PostgreSQL sessions that went smoothly
```

**Keyboard shortcuts:** `Ctrl+1` to `Ctrl+7` switch tabs, `Ctrl+F` jumps to the packet filter, the arrow keys step through packets, and double-clicking a packet opens its connection.

## How it is put together

```text
src/
  shared/types.ts         types shared by the main process and the UI
  main/                   Electron main process: capture and analysis
    main.ts               window, IPC, capture sources, import and export
    engine.ts             frame -> decode -> connections -> detectors -> stats
    capture/
      live.ts             finds dumpcap / tcpdump, lists interfaces, reads their output
      tzsp.ts             MikroTik stream listener and TZSP unwrapping
      file.ts, pcap.ts    pcap / pcapng / gzip reading, pcapng writing
      demo.ts             the simulated demo network
    dissect/              Ethernet, ARP, IPv4/6, TCP, UDP, ICMP, DNS, DHCP,
                          HTTP, TLS, QUIC, SSH, FTP, POP3, IMAP, SMTP, Telnet
    analysis/             connections, detectors, statistics, explanations
  renderer/               the interface, in plain TypeScript with no framework
```

The engine processes roughly 100,000 packets per second on an ordinary laptop. The packet list keeps the most recent 300,000 packets for viewing and export; beyond that, statistics, connections and alerts carry on updating.

## A note on privacy

Packet captures are sensitive. They can contain passwords, cookies and private messages from anything that was not encrypted. Packet Inspector masks the secrets it recognizes in its decoded views, explanations and CSV exports, but the raw bytes in the hex view and in saved `.pcapng` files contain whatever was sent. Only capture networks you are responsible for, and treat the files like you would treat passwords. The `.gitignore` in this repository keeps capture files out of version control for exactly this reason.

## License

MIT
