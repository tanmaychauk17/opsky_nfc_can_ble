# UWB Stack References (Local)

This project references Qorvo UWB stack documentation available locally on your system. The following files were found under `/home/admin/uwb-stack/`:

- uwb-fira-protocol-R12.7.0-405.pdf — FiRa protocol overview and behaviors.
- uwb-uci-messages-api-R12.7.0-405.pdf — UCI (UWB Command Interface) message formats and sequences.
- uwb-l1-api-R12.7.0-405.pdf — Layer 1 (PHY) API surface.
- uwb-l1-configuration-R12.7.0-405.pdf — PHY configuration parameters (channels, PRF, preamble, etc.).
- uwb-uwbmac-api-R12.7.0-405.pdf — UWB MAC layer API.
- uwb-qhal-api-R12.7.0-405.pdf — Qorvo Hardware Abstraction Layer API.
- uwb-qosal-api-R12.7.0-405.pdf — Qorvo OS Abstraction Layer API.
- uwb-qplatform-api-R12.7.0-405.pdf — Qorvo Platform API.

## How we use these docs here

- Nearby Interaction token handling: Align the UWB session setup (INITF/RESPF equivalents) with FiRa and UCI sequences from the UCI Messages and FiRa protocol docs.
- PHY parameters: Map iOS/session-provided constraints to L1 config (channel, PRF set, preamble, STS, etc.), then format them into commands for the module.
- UART → Firmware mapping: If using CLI firmware, translate UCI/FiRa into the module’s CLI (e.g., INITF -VUPPER, THREAD), otherwise use UCI where supported.
- Timing and session state: Follow MAC/UCI state machine guidance for starting/stopping ranging, error recovery, and timeouts.

## Suggested reading order

1. uwb-fira-protocol-… — understand the ranging protocol and roles.
2. uwb-uci-messages-api-… — learn the command and event flow.
3. uwb-l1-configuration-… — map parameters to the radio.
4. uwb-uwbmac-api-… — delve into session states and scheduling.

## Local path

All files above are on this machine at:

```
/home/admin/uwb-stack/
```

If you move these docs, set an environment variable so scripts can reference them in logs:

```
export UWB_DOCS_DIR=/home/admin/uwb-stack
```

Now, `uwb_ble_test.py` will include a pointer when verbose mode is on.
