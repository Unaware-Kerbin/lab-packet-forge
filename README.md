# Lab Packet Forge

**Lab Packet Forge** is a containerlab-native traffic generator with a browser UI for **Templates** and **Craft** modes. It builds lab-valid frames with Scapy from a registry-first protocol catalog—hundreds of L2–L7 / control-plane templates with field schemas, soft/hard PPS caps, and a gateway killswitch.

> Isolated lab use only. Control-plane and flood templates can stress switches and routers; keep rates low on shared fabrics.

## What’s in the box

| Piece | Role |
| --- | --- |
| `trafficgen/` | FastAPI app, static UI, Scapy builders, Docker image |
| `trafficgen/trafficgen.clab.yml` | Minimal clab topology (bridge + privileged trafficgen) |
| `trafficgen/scripts/check_catalog.py` | Ensures every protocol has template + craft + build |

**Product name:** Lab Packet Forge  
**Image:** `lab-packet-forge/trafficgen:1.0`  
**Default UI:** `http://<host>:8080`

## Quick start (containerlab)

```bash
cd trafficgen
docker build -t lab-packet-forge/trafficgen:1.0 .
sudo clab deploy -t trafficgen.clab.yml
# UI → http://<lab-host>:8080
```

Environment knobs (also set in the Dockerfile / clab file):

| Variable | Purpose |
| --- | --- |
| `FORGE_IFACE` | TX interface inside the container (default `eth1`) |
| `FORGE_GATEWAY_KILL` | `1`/`0` — stop TX if probe target(s) unreachable |
| `FORGE_GATEWAY_KILL_TARGET` | Probe IP(s), or empty/`auto` = container default GW |
| `FORGE_LAB_GATEWAY` | Lab/DUT GW hint (e.g. `10.1.0.1`) |
| `FORGE_GATEWAY_KILL_TIMEOUT_S` | Seconds unreachable before auto-stop (default `120`) |

## UI

- **Templates** — pick a protocol, edit fields, set pps/iface, Start/Stop  
- **Craft** — stack the same registry layers with stack warnings  
- **Killswitch** — ICMP probe target in the top bar (`auto` or DUT/lab GW)  
- **Allow dangerous rate** — required to exceed hard PPS caps on floody/control-plane templates  

## Safety

- Per-protocol **soft** (UI guidance) and **hard** (reject without override) PPS caps for ARP, STP family, LLDP/CDP, IGMP/MLD, DHCP, BUM/UUF floods, routing PDUs, and more  
- **Gateway killswitch** stops TX if configured probe target(s) stay unreachable  
- Frames are lab stimuli / header skeletons—not production-grade stacks or attack tooling  

## Protocol catalog (overview)

The registry is modular (`app/registry/*.py`). Categories include:

- **Virtual Chassis / stacking** — vendor VC/MLAG/SVL/iStack presets  
- **L2 / switching** — Ethernet, VLAN/QinQ, STP family, LLDP(+full TLVs), LACP, MACsec, PTP, MRP, ERP/G.8032, TRILL, FCoE/FIP, RoCEv2, PBB/SPB skeletons, OpenFlow Hello, …  
- **L3 / addressing & ICMP** — ARP/GARP, IPv4/IPv6, ICMP, IPv6 extension headers, NDP options, SRv6, HIP, Mobile IP, IGMP/MLDv2, …  
- **L4 / transport** — UDP, TCP, SCTP (+ DATA/PPID), DCCP, QUIC Initial probe  
- **Routing & first-hop** — OSPF/IS-IS/BGP PDUs, RIP, EIGRP, VRRP/HSRP/GLBP, PIM, BFD, LDP, RSVP/RSVP-TE, MSDP, BMP, PCEP, Babel, …  
- **Tunnels / overlays** — GRE(+key), IPIP, VXLAN/VXLAN-GPE, GENEVE(+options), NVGRE, ERSPAN, MPLS, GUE/FOU, EtherIP, NSH, L2TP/L2TPv3, WireGuard/OpenVPN-shaped, …  
- **Telecom / mobile** — GTP-C/U, Diameter, SIP, RTP/RTCP, PFCP, Skinny, Megaco  
- **Industrial / OT** — Modbus/TCP, OPC UA Hello, BACnet, PROFINET DCP, EtherNet/IP, MQTT, CoAP, EtherCAT  
- **Discovery / ops / app** — DHCP(v6), DNS/DNSSEC-shaped, mDNS/LLMNR/SSDP, NTP, SNMP, syslog, RADIUS/TACACS, STUN, TFTP, LDAP, Kerberos-shaped, …  
- **Security-shaped** — IPsec AH/ESP, IKEv2/ISAKMP, EAP-MD5/TLS, TLS/DTLS/HTTP2 probes, SSH banner  
- **Escape hatches** — raw L2/IPv4/IPv6, PCAP replay  

Verify locally:

```bash
cd trafficgen
python scripts/check_catalog.py
```

## Development

```bash
cd trafficgen
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Architecture stays **registry-first**: every protocol registers `fields`, `build()`, and `TemplateMeta` so Templates and Craft share one schema.

## License

MIT — see [LICENSE](LICENSE).
