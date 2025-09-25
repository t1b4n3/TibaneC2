#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//extern int string_len(char *str);
extern int sum(int k);

int main() {
    int total = sum(10);

    printf("%d \n", total);

    return 0;
}
