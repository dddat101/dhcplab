# Troubleshooting Runbook

1. **Stale PID Detection**: Check `is_pidfile_running` or execute `./scripts/show_state.sh`.
2. **Virtual Bridge MAC Flapping**: Ensure deterministic MAC generation (`02:00:00:00:01:xx`) and flush FDB via `bridge fdb flush dev br-lan`.
3. **dumpcap Privilege Drop**: Always capture via `tcpdump -ni <dev> -w <file.pcap>`, and analyze post-mortem via `tshark`.
