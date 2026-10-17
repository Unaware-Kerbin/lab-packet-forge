# Lab Packet Forge — test results

Date: 2026-10-17  
Lab host: `random@10.1.0.10`  
Topology used: `trafficgen/examples/forge-vendor-peers.clab.yml` (`forge-vendors`)

## Catalog

| Check | Result | Notes |
| --- | --- | --- |
| `docker exec clab-forge-vendors-trafficgen python3 /opt/trafficgen/scripts/check_catalog.py` | **PASS** | `registered=176 expected=176`; build smokes OK |
| Host interpreter without Scapy | skip | Use container (or project `.venv`) |

## Vendor inventory (images on lab host)

| Vendor | Image tag | Peer in temp lab |
| --- | --- | --- |
| Aruba | `vrnetlab/aruba_arubaos-cx:10.18.1002` | trafficgen `eth1` |
| Juniper | `vrnetlab/juniper_vjunos-switch:24.4R2-S2.6` | trafficgen `eth2` |
| Cisco | `vrnetlab/cisco_n9kv:10.1.1` | trafficgen `eth3` |

Also present (not required): CSR1000v, vSRX, vJunos-router, Apstra.

## Peer matrix (`scripts/vendor_peer_smoke.py`)

Wire = tcpdump on peer container `eth1` (clab veth into vrnetlab).

Green run (`/tmp/forge_vendor_peer_report.json` on lab host): **27/27 PASS**.

| Peer | Docker health | Link | UDP / LLDP / ARP / STP / BUM smoke | Stress ~200 pps UDP |
| --- | --- | --- | --- | --- |
| Aruba AOS-CX | healthy | **PASS** | **PASS** (wire≥1 each) | **PASS** (wire=200, pps≈199) |
| Juniper vJunos-switch | healthy | **PASS** | **PASS** (wire≥1 each) | **PASS** (wire=200, pps≈200) |
| Cisco N9Kv | unhealthy\* | **PASS** | **PASS** (wire≥1 each) | **PASS** (wire=200, pps≈200) |

\*N9Kv Docker healthcheck remained **unhealthy**, but the peer veth still received forge frames. Treated as NOS/vrnetlab health flake, not a forge TX failure.

## Safety / close-out

| Check | Result |
| --- | --- |
| ARP hard-cap reject | **PASS** |
| BUM hard-cap reject | **PASS** |
| Killswitch target `10.1.0.1` | **PASS** (configured; ICMP OK from trafficgen) |
| TX left stopped | **PASS** (when API still up) |

## Root causes of recent shell exit-1s

| Failure | What it was **not** | Actual cause |
| --- | --- | --- |
| Upload tarball + vendor smoke (24/27) | SSH/scp/disk/image | Harness: `int(errors or 1)==0` fails when `errors==0` despite good wire/pps |
| SSH sync rebuild + retest (25/27) | Sync/docker build (`BUILD_OK`) | Stale `/tmp/forge_stress.count` race; agent `rsync` blocked by sandbox netns (use `ssh … < tarball`) |
| Catalog in-container + vendor smoke (24/27) | Catalog / peer readiness | Catalog **PASS**; all peer smokes **PASS**. Stress `wire=0` from `docker exec … &` killing tcpdump; TX was ~200 pps. Later re-run: Aruba stress failed only `running_mid=False` with healthy pps; suite then hit `ConnectionResetError` when vendor lab was replaced by solo `forge` mid-flight |

## Sync note

From this Cursor agent sandbox, bare `ssh -F ~/.ssh/config -o BatchMode=yes` works (allowlisted). `rsync`/`scp` often hit “Network is unreachable” in the sandbox netns. Reliable sync: `tar czf … && ssh … 'tar xzf - -C …' < archive.tgz`.
