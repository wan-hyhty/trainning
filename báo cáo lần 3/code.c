#include <stdio.h>
#include <stdlib.h>

int main() {
    // Cấp phát 3 khối bộ nhớ kích thước 8 bytes
    int* ptr1 = malloc(8);
    int* ptr2 = malloc(8);
    int* ptr3 = malloc(8);
    // Giải phóng khối bộ nhớ thứ hai
    free(ptr2);

    // Cấp phát một khối bộ nhớ mới
    int* ptr4 = malloc(8);

    // In địa chỉ của các khối bộ nhớ
    printf("Address of ptr1: %p\n", ptr1);
    printf("Address of ptr2: %p\n", ptr2);
    printf("Address of ptr3: %p\n", ptr3);
    printf("Address of ptr4: %p\n", ptr4);

    return 0;
}