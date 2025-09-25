#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int string_len(char *str);

int main() {
    char name[0x20] = "Nkateko";
    int size = string_len(name);
    printf("Name : %s is %d long\n", name, size);
    return 0;
}