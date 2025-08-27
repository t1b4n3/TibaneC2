# Communication 


Server communicates with both implants and operator console by sending json over the network
## Server <-> Implant communication

### Beacon Implants
On first connection beacons register to the C2 server. The implant sends some data about the system and then it receives a agent id to store on disk 
#### Register
##### Implant Sends
```json
{
	"mode":"register",
	"hostname":"",
	"os":"",
	"arch":""
}
```

##### Receives this from server

```json
{
	"mode":"ack",
	"implant_id":"xxx"
}
```

#### Beacon

Every time the beacon implant process starts up on the compromised host the implant checks if the implant_id exists in disk and saves it in memory, if the implant_id file does not exist the implant will register again.
When beaconing.

##### Beacon sends
```json
{
	"mode":"beacon",
	"implant_id":"xxxx",
}
```

Beacon Receives tasks (If task is available), executes tasks and sends back response


##### If task is not available it receives 
```json
{
	"mode":"none"
}
```

##### If tasks are available

```json
{
	"mode":"task",
	"task_id": "123",
	"implant_id":"xxx",
	"command":"whoami",
}
```

it then executes the command and sends back response 

```json
{
	"mode":"result",
	"task_id":"123",
	"implant_id":"xxx",
	"response":"developer",
}
```

### Session Implants

#### Coming Soon

---

## Server <-> Operator Console

### Authentication
First the console must authenticate with the server (3 tries)

```json
{
	"username":"user",
	"password":"pass"
}
```

Server tries to authenticate and send results

#### Authenticated

```json
{
	"authenticated":"true"
}
```

#### Not Authenticated

```json
{
	"authenticated":"false"
}
```

### Getting Data About Implants

#### Implants Information

```json
{
	"Info":"Implants"
}
```

#### All Tasks

```json
{
	"Info":"Tasks"
}

```

#### Logs

```json
{
	"Info":"Logs"
}
```
### Interacting with data for a single implant

#### confirm implant_id

```json
{
	"Info":"verify_implant",
	"impland_id":"xxx"
}
```

```json
{
	"valid_id":"false / true"	
}
```
#### List All Tasks For Specific Beacon

```json
{
	"Info":"implant_id",
	"implant_id":"xxx",
	"action":"x"
}
```

Options for x are  `list-tasks, response-task, new-task`, `update-task` (will update only if the task is not completed)

If x is list-tasks
No json is added and the json is send 

response will be 

if x is new_task
```json
{
	"command":"whoami"
}
```

if x is response-task

```json
{
	"task_id":123
}
```

update-task
```json
{
	"update": "true"
}
```

---