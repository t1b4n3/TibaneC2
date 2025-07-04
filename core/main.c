#include <stdlib.h>
#include <pthread.h>

#include "db.h"
#include "operator.h"
#include "agent.h"

int main() {
    if (db_conn() == -1) {
        perror("Database Failed to connect");
        exit(1);
    }
    pthread_t operator_thread, agent_thread;
    if (pthread_create(&operator_thread, NULL, Operator_conn, NULL) != 0) {
        perror("Failed to start Operator thread");
        exit(1);
    }

    if (pthread_create(&agent_thread, NULL, tcp_listener, NULL) != 0) {
        perror("Failed to start Operator thread");
        exit(1);
    }

    // Wait for threads to finish (if they ever do)
    pthread_join(operator_thread, NULL);
    pthread_join(agent_thread, NULL);

    db_close();
    return 0;
}

