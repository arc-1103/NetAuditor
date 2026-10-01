# Parser sandboxing and ReDoS / prompt-injection defence

Device configs are attacker-influenced text. The parsing service treats them
that way at two layers.

## In the code (`services/parsing/app/input_guard.py`)

- Lines longer than `MAX_LINE_CHARS` (2000) are truncated — regex cost grows
  with line length, so this is the main anti-ReDoS lever.
- Lines that look like instructions to a model ("ignore previous
  instructions", "you are now", "system prompt", ...) are replaced with a
  neutral comment before any parser or model sees them. Line numbers are
  preserved. Every change is logged and returned as `security_flags`
  (kept in the run's review detail when a run needs human review).
- Vendor/OS detection runs in a separate process killed after
  `PARSE_TIMEOUT_SECONDS`; a timeout sends the run to human review instead of
  hanging the worker. The mock extractor already ran this way.
- The model prompt marks the config as untrusted data between
  `<<<BEGIN_CONFIG` and `END_CONFIG>>>` and tells the model never to follow
  instructions found there. Model output is still schema-validated and never
  makes compliance decisions.

## In the container (`docker-compose.yml`, service `parsing`)

Runs as a non-root user with a read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, and limits on processes, memory and
CPU. Docker's default seccomp profile stays on.

Optional stronger isolation (host-dependent, not enabled by default):
- **gVisor**: install `runsc`, then set `PARSER_RUNTIME=runsc`.
- **AppArmor**: load a profile on the host and add `apparmor=<name>` to the
  service's `security_opt`.
- **Custom seccomp**: start from Docker's default profile and remove syscalls
  the worker doesn't need; test with a full parse before enabling.

## Limits

The TextFSM extractor still runs in-process (bounded only by the line cap);
the injection patterns are heuristics and will miss novel phrasing. The
container limits are what contain a successful exploit.
