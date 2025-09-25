#include <stdio.h>
#include <stdlib.h>

// twoSum is implemented in ASM (extern declaration)
int* twoSum(int* nums, int numsSize, int target, int* returnSize);

void run_test(int *nums, int numsSize, int target) {
    int returnSize = 2; // always 2 indices
    int *result = twoSum(nums, numsSize, target, &returnSize);

    if (result != NULL) {
        printf("Target: %d -> Indices: [%d, %d]\n", target, result[0], result[1]);
        free(result);
    } else {
        printf("Target: %d -> No solution found\n", target);
    }
}

int main() {
    // Example 1
    int nums1[] = {2, 7, 11, 15};
    run_test(nums1, 4, 9);   // Expect [0, 1]

    // Example 2
    int nums2[] = {3, 2, 4};
    run_test(nums2, 3, 6);   // Expect [1, 2]

    // Example 3
    int nums3[] = {3, 3};
    run_test(nums3, 2, 6);   // Expect [0, 1]

    return 0;
}
