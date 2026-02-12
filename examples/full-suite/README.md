# Full Suite Demo

This demo includes two projects:

- `dep-service`: dependency project with a server process
- `app-suite`: app project that depends on `dep-service` and runs server + agent + terminal + editor + browser launch

## Run

```bash
cd ~/Code/projd/examples/full-suite/app-suite
proj up
```

This will auto-register and start both projects due to `depends_on = ["../dep-service"]`.

## Explore

```bash
proj list
proj status
proj status --json
proj logs app-suite
proj logs app-suite server
proj logs dep-service server
proj switch dep-service
proj switch app-suite
proj suspend app-suite
proj resume app-suite
proj-tui
```

## Cleanup

```bash
proj down app-suite
proj down dep-service
```
