"""Industrial / OT / IoT application protocols for lab stimulus."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

try:
    from scapy.contrib.modbus import ModbusADURequest, ModbusPDU01ReadCoilsRequest
except Exception:
    ModbusADURequest = ModbusPDU01ReadCoilsRequest = None  # type: ignore

try:
    from scapy.contrib.enipTCP import ENIP_TCP, ENIP_SendUnitData
except Exception:
    ENIP_TCP = ENIP_SendUnitData = None  # type: ignore

try:
    from scapy.contrib.pnio_dcp import ProfinetDCP, DCP_ServiceIDIdentify
except Exception:
    try:
        from scapy.contrib.pnio_dcp import ProfinetIO  # type: ignore

        ProfinetDCP = ProfinetIO
        DCP_ServiceIDIdentify = None  # type: ignore
    except Exception:
        ProfinetDCP = DCP_ServiceIDIdentify = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "modbus_tcp",
    "opcua_hello",
    "bacnet",
    "profinet_dcp",
    "enip",
    "mqtt",
    "coap",
    "ethercat",
)


def _e(c):
    return Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


def _modbus(c):
    if ModbusADURequest is not None and ModbusPDU01ReadCoilsRequest is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / TCP(sport=40000, dport=int(cfg(c, "dport", 502)), flags="PA", seq=1, ack=1)
                / ModbusADURequest(transId=int(cfg(c, "tid", 1)), unitId=int(cfg(c, "unit", 1)))
                / ModbusPDU01ReadCoilsRequest(startAddr=int(cfg(c, "addr", 0)), quantity=int(cfg(c, "qty", 1)))
            )
        except Exception:
            pass
    pdu = bytes([int(cfg(c, "unit", 1)), 0x01]) + struct.pack("!HH", int(cfg(c, "addr", 0)), int(cfg(c, "qty", 1)))
    adu = struct.pack("!HHH", int(cfg(c, "tid", 1)), 0, len(pdu)) + pdu
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 502)), flags="PA", seq=1, ack=1)
        / Raw(adu)
    )


register(
    ProtocolEntry(
        id="modbus_tcp",
        name="Modbus/TCP",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 502),
            field("unit", "Unit ID", "int", True, 1),
            field("addr", "Start address", "int", True, 0),
            field("qty", "Quantity", "int", True, 1),
            field("tid", "Transaction ID", "int", False, 1, advanced=True),
        ],
        build=_modbus,
        template=TemplateMeta("Modbus Read Coils request", "ICS / PLC path labs"),
    )
)


register(
    ProtocolEntry(
        id="opcua_hello",
        name="OPC UA Hello",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 4840),
            field("endpoint", "Endpoint URL", "text", False, "opc.tcp://10.0.0.2:4840", advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 4840)), flags="PA", seq=1, ack=1)
        / Raw(
            b"HELF"
            + struct.pack("<I", 8 + 16 + len(str(cfg(c, "endpoint", "opc.tcp://10.0.0.2:4840")).encode()))
            + struct.pack("<IIII", 0, 65536, 65536, 0)
            + str(cfg(c, "endpoint", "opc.tcp://10.0.0.2:4840")).encode()
        ),
        template=TemplateMeta("OPC UA Hello (HEL) message", "Industrial OPC path labs"),
    )
)


register(
    ProtocolEntry(
        id="bacnet",
        name="BACnet/IP Who-Is",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", False, "255.255.255.255", advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip", "255.255.255.255"))
        / UDP(sport=47808, dport=47808)
        / Raw(bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])),
        template=TemplateMeta(
            "BACnet/IP Who-Is broadcast",
            "Building automation discovery labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


def _pn_dcp(c):
    if ProfinetDCP is not None:
        try:
            return (
                Ether(dst="01:0e:cf:00:00:00", src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x8892)
                / ProfinetDCP()
            )
        except Exception:
            pass
    # DCP Identify request skeleton
    return Ether(dst="01:0e:cf:00:00:00", src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x8892) / Raw(
        bytes([0xFE, 0xFE, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0x00, 0x00])
    )


register(
    ProtocolEntry(
        id="profinet_dcp",
        name="PROFINET DCP Identify",
        category="Industrial / OT",
        layer="app",
        craft_slot="l2",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
        ],
        build=_pn_dcp,
        template=TemplateMeta(
            "PROFINET DCP Identify multicast",
            "Industrial Ethernet discovery labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


def _enip(c):
    if ENIP_TCP is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / TCP(sport=40000, dport=int(cfg(c, "dport", 44818)), flags="PA", seq=1, ack=1)
                / ENIP_TCP(commandId=0x0065, session=int(cfg(c, "session", 0)))  # RegisterSession
            )
        except Exception:
            pass
    # RegisterSession
    body = struct.pack("<HHIIQI", 0x0065, 4, 0, 0, 0, 0) + struct.pack("<HH", 1, 0)
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 44818)), flags="PA", seq=1, ack=1)
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="enip",
        name="EtherNet/IP RegisterSession",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 44818),
            field("session", "Session handle", "int", False, 0, advanced=True),
        ],
        build=_enip,
        template=TemplateMeta("CIP EtherNet/IP RegisterSession", "Rockwell / CIP path labs"),
    )
)


def _mqtt(c):
    try:
        from scapy.contrib.mqtt import MQTT, MQTTConnect
    except Exception:
        MQTT = MQTTConnect = None  # type: ignore
    client = str(cfg(c, "client_id", "forge")).encode()
    if MQTT is not None and MQTTConnect is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / TCP(sport=40000, dport=int(cfg(c, "dport", 1883)), flags="PA", seq=1, ack=1)
                / MQTT()
                / MQTTConnect(clientId=client.decode())
            )
        except Exception:
            pass
    # MQTT CONNECT fixed header + variable
    proto = b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack("!H", len(client)) + client
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 1883)), flags="PA", seq=1, ack=1)
        / Raw(bytes([0x10, len(proto)]) + proto)
    )


register(
    ProtocolEntry(
        id="mqtt",
        name="MQTT CONNECT",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 1883),
            field("client_id", "Client ID", "text", True, "forge"),
        ],
        build=_mqtt,
        template=TemplateMeta("MQTT CONNECT", "IoT broker path labs"),
    )
)


register(
    ProtocolEntry(
        id="coap",
        name="CoAP GET",
        category="Industrial / OT",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 5683),
            field("path", "URI path", "text", True, ".well-known/core"),
            field("msgid", "Message ID", "int", False, 1, advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=int(cfg(c, "dport", 5683)))
        / Raw(
            bytes([0x40, 0x01])  # ver=1 CON GET
            + struct.pack("!H", int(cfg(c, "msgid", 1)))
            + b"".join(
                bytes([0xB0 | (len(p) & 0x0F)]) + p.encode()
                for p in str(cfg(c, "path", ".well-known/core")).strip("/").split("/")
            )
        ),
        template=TemplateMeta("CoAP CON GET", "Constrained device / IoT labs"),
    )
)


register(
    ProtocolEntry(
        id="ethercat",
        name="EtherCAT frame",
        category="Industrial / OT",
        layer="app",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("payload_hex", "Datagram body (hex)", "hex", False, "00" * 32, advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x88A4)
        / Raw(struct.pack("<H", 0x1000 | len(hex_bytes(cfg(c, "payload_hex", "00" * 32)))) + hex_bytes(cfg(c, "payload_hex", "00" * 32))),
        template=TemplateMeta("EtherCAT Ethernet frame skeleton", "Hard realtime industrial labs"),
    )
)
