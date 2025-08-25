#!/bin/bash



if [[ "$1" == "POST" ]]; then
	curl -X POST http://localhost:8000/api/$2/$3 \
		-d "cmd=$4"
elif [[ "$1" == "GET" ]]; then 
	curl http://localhost:8000/api/$2/$3
elif [[ "$1" == "PUT" ]]; then 
	curl -X PUT http://localhost:8000/api/$2/$3 \
		-d "cmd=$4"
else 
	echo "ENTER A Request method"
	echo "$0 [REQUEST_METHOD] ..."
fi


