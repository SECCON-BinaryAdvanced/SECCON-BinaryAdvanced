#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int year = 2026 - 1900;
int mon = 2;
int mday = 6;
int hour = 3;
int min = 13;
int sec = 37;

int main() {
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);

    if (!(lt->tm_year == year
            && lt->tm_mon == mon
            && lt->tm_mday == mday
            && lt->tm_hour == hour
            && lt->tm_min == min
            && lt->tm_sec == sec)) {
        exit(0);
    }

    printf("Malicious behavior invoked!\n");

    return 0;
}