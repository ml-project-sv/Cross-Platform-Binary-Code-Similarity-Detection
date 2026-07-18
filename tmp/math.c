int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    int c = add(a, -b);

    if (a == 0) {
        return b;
    }
    return c;
}


int analyze_scores(int *scores, int n)
{
    int total = 0;
    int passed = 0;
    int failed = 0;
    int highest = -1;
    int swaps = 0;
    int i, j;

    for (i = 0; i < n; i++) {
        int s = scores[i];

        if (s < 0) {
            s = 0;         
        } else if (s > 100) {
            s = 100;        
        }

        total += s;

        if (s >= 90) {
            passed++;
        } else if (s >= 75) {
            passed++;
        } else if (s >= 50) {
            passed++;
        } else {
            failed++;
        }

        if (s > highest) {
            highest = s;
        }
    }

    if (n == 0) {
        return -1;     
    }

    for (i = 0; i < n - 1; i++) {
        for (j = 0; j < n - 1 - i; j++) {
            if (scores[j] > scores[j + 1]) {
                int tmp = scores[j];
                scores[j] = scores[j + 1];
                scores[j + 1] = tmp;
                swaps++;
            }
        }
    }

    if (passed > failed) {
        if (highest == 100) {
            return total / n + 2;
        }
        return total / n + 1;
    }

    if (swaps > n) {
        return total / n - 1;
    }

    return total / n;
}
