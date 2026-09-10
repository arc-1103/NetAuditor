# Evidence benchmark

Capture the JSON response for every file in `demo/` as
`<fixture-name>.json`, then run:

```bash
python benchmarks/score_demo_results.py benchmark-results \
  --output benchmark-results/metrics.json
```

The command fails if a reviewed required finding is missed, a reviewed
negative finding appears, or vendor detection is wrong. Add real, independently
reviewed configurations before quoting accuracy outside the three-fixture demo.

Latency and throughput must be recorded around the complete live pipeline on
the presentation machine. Architecture targets are not benchmark results.
