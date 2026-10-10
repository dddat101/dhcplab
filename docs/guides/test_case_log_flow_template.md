# Gateway Performance Lab: Standard Log Flow Template

To keep the log output of every test case coherent, readable, and easy to debug, we should adhere to a **3-Phase** template. A clear separation between the Setup, Execution, and Audit phases prevents analytical logs (large tables) from being scattered and interleaved with execution logs.

## 1. Phase 1: Environment & Profile (Setup)
The goal of this phase is to initialize the environment, connect to the DUT, print the test configuration, and start packet captures. Commands that retrieve state data (such as EDCA parameters) should be executed silently (`--quiet`) and only log brief status messages.

```text
==================================================================
  STARTING GATEWAY PERFORMANCE TEST: [<TEST_NAME>]
==================================================================
[INFO]    Starting Dual/Multi-side Packet Capture [<test_tag>] (Snaplen: 96B):
[INFO]      -> WAN Interface    : ...
[INFO]      -> LAN PC Interface : ...
[PASS]    Multi-point captures active: WAN (PID X) | LAN (PID Y)
===> [TC-XXXX-XX] <Test Description>
[INFO]    Test Multi-Service Profile:
[INFO]      -> Mode                    : ...
[INFO]      -> Test Duration           : ...
[INFO]    Extracting state/configurations via DUT Collector... (Silently)
===> Fetching Initial Parameters (e.g. WMM EDCA)... 
```
> **Best Practice:** Do not print large audit tables in this step. If a baseline state is needed, save it to a temporary JSON/Text file to be used in the final Audit phase.

## 2. Phase 2: Execution (Run Steps)
The goal is to execute the traffic flow / traffic injection. Only print critical milestones so the user can track the progress.

```text
[INFO]    Starting upstream servers in ns-wan...
[INFO]    Starting concurrent clients on Wi-Fi endpoint...
[PASS]    Traffic stream 1 & 2 active. Now injecting background traffic...
[INFO]    Traffic injection running for 10s...
[INFO]    Stopping traffic clients...
[INFO]    Test Execution Completed.
[INFO]    Stopping capture processes simultaneously (PIDs: X, Y)...
```

## 3. Phase 3: Audit & Evaluation (Post-Test)
After all capture and traffic processes have stopped, we analyze the PCAPs and correlate the logs. This is the optimal time to print detailed Audit Tables to present the conclusions.

```text
====================================================================================================
  <COMPONENT 1> PARAMETERS AUDIT & FIELD VALUES (e.g., IEEE 802.11e WMM EDCA)
====================================================================================================
  Target BSSID     : ...
  ...
----------------------------------------------------------------------------------------------------
  OVERALL VERDICT: PASS
====================================================================================================

================================================================================
  <COMPONENT 2> TRAFFIC AUDIT (e.g., QoS DSCP MAPPING)
================================================================================
  WAN Ingress Capture : ...
  LAN Egress Capture  : ...
--------------------------------------------------------------------------------
SERVICE CLASS      DSCP (TOS)   ...    LOSS %   STATUS
--------------------------------------------------------------------------------
Voice (VoIP/VoWi)  46 (0xb8)    ...    0.0%     PASS
--------------------------------------------------------------------------------
  OVERALL VERDICT: PASS (Criteria Satisfied)
================================================================================

[PASS]    Scenario run complete. Summary logs generated in /logs/.

Suggested next steps:
  - Inspect captures:        ./scripts/capture.sh status
  - Audit dual captures:     ./scripts/capture.sh compare
```

### Improvements implemented in `06_wireless_qos.sh`:
- Added the `--quiet` flag to the `wireless_qos_audit.py --audit-wmm` function call in **Phase 1**. As a result, instead of blocking the view with the WMM EDCA Audit table during test preparation, the script simply displays `[===> Fetching WMM EDCA Parameters...]` and silently saves the JSON file.
- All WMM Audit results, along with the QoS Traffic Audit, will only be aggregated and displayed simultaneously in **Phase 3** (when `capture.sh compare` is invoked at the end), restoring a clear flow as outlined in the template above.
