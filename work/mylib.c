int add(int a, int b) {

    if (a == 0) {
        return 0;
    }

    int c = a + b;
    return c;
}

int sub(int a, int b) {
    int c = a - b;
    return c;
}

int is_prime(int n) {
    if (n < 2) return 0;
    if (n % 2 == 0) return n == 2;
    for (int d = 3; (int)d * d <= n; d += 2) {
        if (n % d == 0) return 0;
    }
    return 1;
}

