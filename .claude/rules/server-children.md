---
paths:
  - server/start_application.*
  - server/start_systemd_unit.*
---
# Application children

- `state_changed_cb` must fire whenever `running()` turns false, on every path that drops a job or
  unit (failed job, failed proxy, unit already stopped when its proxy is created).
  - Otherwise `update_fsm` never learns the application is gone and quitting hangs.
- `forked_children::stop()` can be called repeatedly; it must not replace a pending SIGKILL timer,
  or the old one fires on a reaped (possibly reused) process group.
