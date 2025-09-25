#include <stdio.h>
#include <stdlib.h>
#include <string.h>


extern int array_sum(int arr[], int size);


int main() {
    int arr[3] = {1, 2, 3};
    int sum = array_sum(arr, 3);
    printf("%d\n", sum);
    return 0;
}