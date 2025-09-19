# CMT - Configuration Management Tool

CMT is a fun experimental project exploring what happens when you rebuild configuration management from scratch in Go. It's a learning experiment in building a modern alternative to tools like Ansible. It's not production-ready, it's not battle-tested, and it definitely shouldn't manage your critical infrastructure.

This project manages Linux servers through SSH with a few core principles:
- Zero dependencies on target hosts
- Single static binary on the control node
- Actual code instead of YAML
- Parallel execution by default
- Type safety and compile-time checks

## Features

- [x] SSH-based remote execution
- [x] Package management (apt/yum)
- [ ] Service management (systemd)
- [ ] File uploads with templates
- [ ] Parallel execution across hosts
- [ ] System detection and facts
- [ ] Windows support (maybe someday)
