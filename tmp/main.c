#include <stdio.h>
#include "math.h"

void foo() {
    printf("foo\n");
}

void bar() {
    printf("bar\n");
}

int main() {
    bar();
    printf("%d\n", add(1, 2));
    return 0;
}