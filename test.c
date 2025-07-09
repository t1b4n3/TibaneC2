#include <stdio.h>


int main() {
    char data[6][0x20][0x100] = {
        {"Agents", {"A", "B", "C"}},
        {"OS", {"D", "E", "F"}},
        {"IP", {"Z", "X", "D"}}
    };

    for (int i = 0;i < 4; i++) {
        printf("%d %d %d\n", data["Agents"][i], data["OS"][i], data["IP"][i]);
    }

    return 0;
}