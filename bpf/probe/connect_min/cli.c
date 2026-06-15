// Connect probe: N non-blocking connects to 127.0.0.2:9099 (matching Rust's
// connect_timeout). EPERM => blocked by the LSM; anything else (success or
// ECONNREFUSED, since there's no listener) => the LSM let it through (leaked).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 500;
    int blocked = 0, leaked = 0, other = 0;
    for (int i = 0; i < N; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) { other++; continue; }
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(9099);
        inet_pton(AF_INET, "127.0.0.2", &a.sin_addr);
        int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
        if (r == 0) {
            leaked++;
        } else if (errno == EPERM) {
            blocked++;
        } else if (errno == EINPROGRESS) {
            struct pollfd pf;
            pf.fd = fd; pf.events = POLLOUT; pf.revents = 0;
            poll(&pf, 1, 250);
            int se = 0; socklen_t sl = sizeof(se);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &se, &sl);
            if (se == EPERM) blocked++; else leaked++;
        } else {
            leaked++;
        }
        close(fd);
    }
    printf("N=%d blocked=%d leaked=%d other=%d\n", N, blocked, leaked, other);
    return 0;
}
