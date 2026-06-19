# Home Network Capture

This lab can ingest live home-network telemetry, but there are important limits.

## What Is Possible from This PC

From a normal Windows laptop or desktop on Wi-Fi, you can reliably capture:

- traffic to and from this PC
- Windows connection metadata such as local address, remote address, ports, state, and process name
- router/firewall syslog if your router can forward logs
- packet captures from this PC using Windows `pktmon`

You usually cannot see every packet from every device on the home network unless one of these is true:

- the router/firewall exports syslog, NetFlow, IPFIX, or similar telemetry
- a managed switch mirrors traffic to this PC
- traffic is routed through this PC
- a proper network tap is used
- the Wi-Fi adapter and driver support monitor mode, and the capture is configured correctly

## Live Windows Connection Telemetry into Splunk

Run this from the repo root:

```powershell
.\scripts\Watch-NetConnections.ps1 -Seconds 900 -IntervalSeconds 5
```

The script writes JSONL to:

```text
data/live_windows_connections.jsonl
```

Splunk monitors this file as:

```spl
index=lab_network sourcetype=splunk_lab:windows_netconn:json
```

Useful SPL:

```spl
index=lab_network sourcetype=splunk_lab:windows_netconn:json
| stats count dc(remote_address) as remote_hosts values(remote_port) as remote_ports by process_name state
| sort - count
```

```spl
index=lab_network sourcetype=splunk_lab:windows_netconn:json remote_address!="127.0.0.1" remote_address!="::1"
| where NOT cidrmatch("10.0.0.0/8", remote_address)
  AND NOT cidrmatch("172.16.0.0/12", remote_address)
  AND NOT cidrmatch("192.168.0.0/16", remote_address)
| stats count values(remote_port) as ports values(process_name) as processes by remote_address
| sort - count
```

## Packet Capture with Windows Pktmon

Run PowerShell as Administrator, then:

```powershell
.\scripts\Start-PktmonCapture.ps1 -Seconds 120
```

This writes `.pcapng` files into:

```text
captures/
```

Splunk is not a packet decoder by default. Use the packet capture for Wireshark/tshark-level packet inspection, and use the JSON connection telemetry or router syslog for Splunk dashboards.

## Router Syslog into Splunk

This lab exposes UDP syslog on host port `5514`:

```text
udp://localhost:5514 -> index=lab_network sourcetype=splunk_lab:router:syslog
```

If your router supports remote syslog:

1. Set the syslog server to this PC's LAN IP address.
2. Set the syslog port to `5514`.
3. Start the Splunk container.
4. Search:

```spl
index=lab_network sourcetype=splunk_lab:router:syslog
| stats count by host source
```

If your router only supports port `514`, you can change the Compose mapping from `5514:5514/udp` to `514:5514/udp`, but Windows may require elevated privileges or firewall changes for low-numbered ports.

## Privacy and Safety

Only capture traffic on networks and devices you own or are explicitly authorized to monitor. Packet captures can include sensitive metadata and sometimes content. Store captures carefully and avoid committing `captures/` to GitHub.
