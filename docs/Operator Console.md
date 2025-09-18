

## Tibane Shell Commands

shell example
```sh
[ tibane-shell ] $
```

- `beacons` : shows all active beacons
- `implants` :  shows all active implants
- `get-implant` : generates implant
- `beacon [id]` : interactive shell for beacons
- `quit` | `exit` | `q` : Exit and close shell
- `list-tasks` : show all tasks, status and responses for all implants
- `new-task` : Add tasks for all implants
	- `new-task [linux/windows]` : Add task for implants in specific operating system.
---
- `history` : view command history
- `clear-history` : clear command history
### Beacon shell

shell example

```sh
[ tibane-shell ] (implant_id) $
```

-  `new-task [task]` issuing new tasks
-  `list-tasks` : list all tasks, status, and responses related to this implant
-  `response-task [task id]` shows task and response
-  `update-task [task id] [cmd]` : update task (only if it is not completed)

