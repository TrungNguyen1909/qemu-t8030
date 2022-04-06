#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include "fuzz.h"

#define READ(_x)    if (fuzzread(0, &_x, sizeof(_x)) < sizeof(_x)) continue

int main() {
    int sock = -1;

    while (true) {
        int domain = 0;
        int type = 0;
        int protocol = 0;
        if (sock >= 0) {
            close(sock);
            sock = -1;
        }
        fuzz_vm_stop();
        fuzz_set_thread();
        if (fuzzread(0, &domain, sizeof(domain)) < 4) {
            continue;
        }
        if (fuzzread(0, &type, sizeof(type)) < 4) {
            continue;
        }
        if (fuzzread(0, &protocol, sizeof(protocol)) < 4) {
            continue;
        }
        sock = socket(domain, type, protocol);
        if (sock < 0) {
            continue;
        }

        int opc = 0;
        while (fuzzread(0, &opc, 1) == 1) {
            switch (opc % 4) {
            case 0: { /* setsockopt */
                int level;
                int option_name;
                int option_len;
                READ(level);
                READ(option_name);
                READ(option_len);
                char buffer[option_len];
                READ(buffer);
                setsockopt(sock, level, option_name, buffer, option_len);
                break;
            }
            case 1: { /* connect */
                socklen_t len;
                READ(len);
                char buffer[len];
                READ(buffer);
                connect(sock, (const struct sockaddr*)buffer, len);
                break;
            }
            case 2: { /* disconnect */
                disconnectx(sock, SAE_ASSOCID_ANY, SAE_CONNID_ANY);
                break;
            }
            case 3: { /* socket */
                int s = -1;
                READ(domain);
                READ(type);
                READ(protocol);
                s = socket(domain, type, protocol);
                if (s < 0) {
                    continue;
                } else {
                    close(sock);
                    sock = s;
                }
                break;
            }
            }
        }

    }
}
