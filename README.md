# P4 GOOSE Security and In-band Network Telemetry

Experimental implementation of **IEC 61850 GOOSE traffic monitoring, spoofing mitigation, and In-band Network Telemetry (INT)** using a **P4-programmable data plane** on BMv2.

The project demonstrates how security logic can be moved into the network data plane to identify suspicious GOOSE traffic, maintain per-flow state, generate controller notifications, and export packet-processing telemetry.

## Overview

IEC 61850 GOOSE (Generic Object Oriented Substation Event) messages are used in electrical substations to distribute time-critical events between Intelligent Electronic Devices (IEDs).

This repository explores a programmable-data-plane approach for two complementary goals:

1. **GOOSE flow validation and spoofing mitigation**
2. **In-band telemetry for switch processing-time measurement**

The P4 program parses GOOSE traffic, maintains state per flow, compares the ingress port associated with a previously observed flow, and can drop packets when the same flow is observed from a different ingress port. It also tracks changes in `stNum` and sends digest notifications to the control plane.

In parallel, the switch creates a cloned telemetry report containing ingress and egress timestamps plus a flow identifier. A Python collector receives those reports and calculates packet-processing latency.

## Key Features

- P4_16 implementation using the **v1model** architecture
- Parsing of IEC 61850 GOOSE Ethernet frames (`EtherType 0x88B8`)
- Per-flow state using P4 registers
- Flow identification using Source MAC + Destination MAC + GOOSE `AppID`
- Detection of the same flow arriving through a different ingress port
- Data-plane packet dropping for suspicious flows
- Tracking of GOOSE `stNum` changes
- Digest notifications from the switch to the controller
- Controller-side digest processing over BMv2 Thrift / Nanomsg
- INT-style telemetry reports using a dedicated EtherType (`0x88B9`)
- Ingress and egress timestamp collection
- Processing-latency calculation in Python
- Egress packet cloning for telemetry export

## Architecture

```text
                      +----------------------+
                      |   Python Controller  |
                      |   Digest Receiver    |
                      +----------^-----------+
                                 |
                           Digest / Nanomsg
                                 |
+---------+      GOOSE     +-----+------+      GOOSE      +---------+
|  IED /  | -------------> |    BMv2    | -------------> |  IED /  |
| Source  |                | P4 Switch  |                | Receiver |
+---------+                +-----+------+                +---------+
                                 |
                                 | cloned telemetry report
                                 | EtherType 0x88B9
                                 v
                      +----------------------+
                      |  Python Collector    |
                      | latency calculation  |
                      +----------------------+
```

## GOOSE Flow Validation

The P4 program creates a flow identifier from:

```text
Source MAC + Destination MAC + AppID
```

A CRC32-based hash maps the flow to a register entry.

For each observed flow, the switch stores the ingress port where the flow was first seen.

```text
First packet of a flow
        |
        v
Store ingress port
        |
        v
Allow packet
```

For subsequent packets:

```text
Known flow
   |
   +--> Same ingress port ------> Allow
   |
   +--> Different ingress port -> Drop
```

The intent is to detect a potential spoofing scenario in which traffic with the same logical GOOSE flow identity appears from a different network attachment point.

> This mechanism is an experimental mitigation strategy and is intended for controlled research environments rather than as a complete IEC 61850 security solution.

## GOOSE State Tracking

The program also maintains the latest observed GOOSE `stNum` for each flow.

When a change in `stNum` is detected, the switch generates a digest containing:

- Source MAC
- Destination MAC
- Ingress port
- AppID
- `stNum`
- `sqNum`

The digest is sent to the control-plane application for further processing.

## In-band Network Telemetry

The switch measures its own packet-processing time using BMv2 timestamps.

The telemetry header contains:

| Field | Size |
|---|---:|
| Ingress timestamp | 48 bits |
| Egress timestamp | 48 bits |
| Flow hash | 32 bits |

The processing latency is calculated by the collector as:

```text
processing_latency = egress_timestamp - ingress_timestamp
```

Telemetry reports use:

```text
EtherType: 0x88B9
```

The original GOOSE frame continues through the normal forwarding path while an egress clone is transformed into a compact telemetry report.

## Repository Structure

```text
p4_goose_int/
├── goose_miti_bmv2.p4   # P4 program: GOOSE parsing, mitigation and telemetry
├── mycontroller.py      # BMv2 controller / digest receiver
├── collector.py         # Telemetry packet collector and latency calculator
└── README.md
```

### `goose_miti_bmv2.p4`

Main data-plane implementation:

- Ethernet and GOOSE parsing
- MAC forwarding
- flow hashing
- register-based state
- ingress-port validation
- packet drop decisions
- `stNum` tracking
- digest generation
- timestamp collection
- telemetry cloning and report generation

### `mycontroller.py`

Python control-plane application:

- connects to a remote BMv2 switch through Thrift
- discovers the notifications socket
- connects to BMv2 notifications using Nanomsg
- decodes GOOSE digest structures
- displays GOOSE flow information
- acknowledges digest buffers

### `collector.py`

Python telemetry collector:

- captures Ethernet packets
- parses the custom telemetry report
- extracts ingress and egress timestamps
- extracts the flow identifier
- calculates processing latency

## Technologies

| Technology | Purpose |
|---|---|
| **P4_16** | Programmable data-plane implementation |
| **BMv2 / simple_switch** | Software P4 target |
| **v1model** | P4 target architecture |
| **Python 3** | Controller and telemetry collector |
| **Scapy** | Packet capture and Ethernet parsing |
| **P4Utils** | BMv2 Thrift interaction |
| **Nanomsg / nnpy** | Digest notification transport |
| **IEC 61850 GOOSE** | Industrial substation communication protocol |
| **Linux** | Experimental environment |

## Important Constants

```text
GOOSE EtherType:      0x88B8
Telemetry EtherType:  0x88B9
Mirror Session ID:    1
Register Size:        4096
```

Some addresses, switch IPs, ports, and mirror configuration values are specific to the original testbed and should be adapted before running the code in another environment.

## Controller Configuration

`mycontroller.py` currently contains testbed-specific configuration values such as:

```python
REMOTE_SWITCH_IP = "192.168.122.78"
THRIFT_PORT = 9090
P4_PROGRAM_NAME = "goosemit"
```

Update these values to match your BMv2 environment.

For remote digest reception, BMv2 notifications must be exposed through a TCP address rather than a local IPC socket, for example:

```bash
--notifications-addr tcp://0.0.0.0:22222
```

## Experimental Workflow

```text
1. Compile the P4 program
2. Start BMv2 with the compiled pipeline
3. Configure forwarding and mirror session
4. Start the Python digest controller
5. Start the telemetry collector
6. Replay or generate IEC 61850 GOOSE traffic
7. Observe:
   - normal forwarding
   - stNum digest notifications
   - spoofing/drop decisions
   - switch processing latency
```

## Research Context

This repository is part of experimental research on the application of **Programmable Data Planes (PDP)** to cybersecurity and telemetry in industrial communication networks.

The implementation explores:

- detecting GOOSE spoofing indicators directly in the data plane
- applying mitigation without waiting for a centralized controller
- measuring the processing overhead introduced by P4 security logic
- using INT-style telemetry to provide visibility into packet-processing latency

## Limitations

This code is a research prototype.

- The GOOSE parser is tailored to the packet layout used in the experimental testbed.
- Flow identification uses a finite register table and a hash, so collisions are theoretically possible.
- Ingress-port consistency is only one indicator of spoofing and is not a complete authentication mechanism.
- Testbed-specific MAC addresses, ports, Thrift endpoints, and mirror configuration may require modification.
- The implementation targets BMv2/v1model and should not be assumed portable to hardware targets without adaptation.

## Potential Extensions

- validation of both `stNum` and `sqNum` state transitions
- richer per-flow behavioral models
- configurable mitigation policies
- export of security events to external monitoring systems
- hardware evaluation on programmable switches
- comparison of data-plane detection latency against controller-based approaches
- integration with broader IEC 61850 anomaly-detection mechanisms

## Author

**Andrés Felipe Osorio Henker**

Electronic Engineer · Telecommunications Research  
Programmable Data Planes · P4 · SDN · Network Telemetry · Critical Infrastructure Security

GitHub: https://github.com/aosorih  
LinkedIn: https://www.linkedin.com/in/andres-felipe-osorio-henker
