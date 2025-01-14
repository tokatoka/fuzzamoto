#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <number>\n", argv[0]);
        return 1;
    }

    int choice = atoi(argv[1]);
    
    switch (choice) {
        case 1: {  // Null pointer dereference
            int *ptr = NULL;
            *ptr = 42;  // CRASH!
            break;
        }
        case 2: {  // Assert
            assert(0 && "Intentional assert crash");
            break;
        }
        case 3: {  // Abort
            abort();
            break;
        }
        case 4: {  // Buffer overflow
            char tiny_buffer[4];
            strcpy(tiny_buffer, "This is way too long!");  // CRASH!
            break;
        }
        case 5: {
            int a = 0;
            int b = 100 / a;       // This will trigger UBSan
            printf("Result: %d\n", b);
            break;
        }
    }

    return 0;
}
