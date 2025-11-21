#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/dev/sgx_enclave", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/sgx_enclave");
        printf("Error: Cannot access SGX device\n");
        printf("Make sure you're in the 'sgx' group: groups\n");
        return 1;
    }
    
    printf("✓ Successfully opened /dev/sgx_enclave\n");
    printf("✓ SGX device is accessible\n");
    close(fd);
    return 0;
}
