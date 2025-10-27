# Implants

TibaneC2 supports two modes:
- beacon mode
	- Implements as communication style where a implant periodically checks in with the server to retrieve tasks, executes them, and returns the results
- session mode
	- Implements a interactive session using either a persistent connection or long polling depending on the protocol used.
## Generating Implants
### Examples


## Interacting with implants
The console `tibane-console` is used to interact with implants
Implants are considered  "active implants" if they have connected to C2 server in the last 30 days.

Command `implants` shows all active implants
### Beacon Mode
Beacons first registers itself with the C2 server, then tries to retrieve tasks, executes them and return results.
Command `beacons` will show all active beacons (implants).
Command `beacon [id]` which will give a shell specifically for the beacon.
Commands about tasks.
1. `new-task [task]` task will be 
2. `list-tasks` : list all tasks, status, and responses related to this implant
3. `response-task [task id]` shows task and response
4. 
### Session Mode
Command `session [id]`  will give a interactive shell.
