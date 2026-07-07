
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    int c = a + b;
    if (a == 0) {
        return b;
    }
    return c;
}
