# DHCP Conformance Test Lab (`dhcplab`)

A network test automation and protocol conformance lab for DHCPv4, DHCPv6, and DHCP Relay on broadband home gateways and routers.

## Language

### Core Domain

**Device Under Test (DUT)**:
The residential gateway, broadband router, or access point undergoing performance and compliance benchmarking.
_Avoid_: router, box, unit, target

**Capture Set**:
The synchronized group of packet capture files recorded across WAN, LAN, Wi-Fi station, or over-the-air sniffer interfaces during a single test run.
_Avoid_: pcap bundle, capture files, trace set

**Audit Profile**:
The formal criteria governing verification stringency, packet loss tolerance, jitter limits, and required access categories for a benchmark run.
_Avoid_: test config, audit mode, test settings

### Evidence Verification

**Packet Evidence Auditor**:
The deep module responsible for evaluating packet preservation, micro-latency, RTP jitter, and 802.11e QoS mapping across capture sets.
_Avoid_: pcap correlator, audit script, verification tool

**Evidence Report**:
The structured record containing cross-DUT frame preservation counts, loss percentages, jitter measurements, and final compliance verdicts.
_Avoid_: test log, audit dump, output json

**Transport Identity**:
An invariant fingerprint extracted from application payload magic signatures, sequence numbers, or protocol identifiers that uniquely identifies a packet across network address translation (NAT).
_Avoid_: packet hash, flow key, packet id

**WMM Classification**:
The verified mapping of IP DiffServ Code Points (DSCP) to IEEE 802.11e Wireless Multimedia Access Categories and Traffic Identifiers (TID).
_Avoid_: wireless qos mapping, priority tag, wme setup

### Benchmark Evaluation

**Benchmark Evaluator**:
The unified domain service responsible for aggregating throughput counters, evaluating degradation tolerances, and determining pass/fail verdicts across test execution phases.
_Avoid_: metric parser, throughput calculator, eval script

**Evaluation Verdict**:
The formal verdict (PASS, FAIL, INCONCLUSIVE, INVALID) determined by mathematical comparison of measured parameters against benchmark tolerance criteria.
_Avoid_: test status, result string, exit flag

**Degradation Tolerance**:
The maximum permissible percentage degradation between baseline and concurrent throughput loads before triggering a benchmark failure.
_Avoid_: margin, diff limit, error threshold

**Terminal Card**:
The standardized visual presentation card displaying multi-stream measurements, target criteria, and color-coded status badges in console output.
_Avoid_: ascii table, printout, summary block

### Traffic Process Supervision

**Traffic Process Supervisor**:
The centralized module responsible for asynchronous process execution, PID registry management, network namespace isolation, graceful termination escalation, and deterministic child reaping.
_Avoid_: background manager, pid killer, spawn helper

**Process Registry**:
The runtime table mapping symbolic job identifiers to operating system process IDs, associated network namespaces, log redirection paths, and command metadata.
_Avoid_: pid list, active jobs, bg table

**Readiness Polling**:
Deterministic socket and port readiness verification that confirms a server or receiver is actively listening before client traffic is initiated, eliminating arbitrary timing delays.
_Avoid_: sleep pause, blind wait, startup grace

**Supervised Job**:
An isolated background test process tracked by the Process Registry with bounded execution lifespan, automated output capture, and fail-safe exit trap registration.
_Avoid_: background pid, child task, worker

### Orchestrator Running Mode & Station Lifecycle

**Running Context Resolver**:
The deep domain module responsible for evaluating laboratory topology constraints, hardware inspection data, and user overrides to generate an immutable, validated Execution Plan.
_Avoid_: mode parser, test mode detector, env config script

**Execution Plan**:
The immutable execution configuration containing the canonical execution mode, resolved endpoint interfaces, associated network namespaces, and required routing/QoS policies for a benchmark run.
_Avoid_: mode string, run profile, config dump

**Station Adapter**:
The polymorphic adapter layer encapsulating network namespace bindings, host routing, DSCP mangle tagging, and scoped cleanup across virtual, local physical, and remote stations.
_Avoid_: wifi helper, route manager, netns wrapper

