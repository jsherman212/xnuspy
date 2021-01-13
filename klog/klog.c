#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv){
    int klog_fd = open("/dev/klog", O_RDONLY);

    if(klog_fd == -1){
        printf("open: %s\n", strerror(errno));
        return 1;
    }

    for(;;){
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(klog_fd, &rfds);

        int res = select(FD_SETSIZE, &rfds, NULL, NULL, NULL);

        if(res < 0){
            printf("select failed: %s\n", strerror(errno));
            close(klog_fd);
            return 1;
        }

        char buf[1024];
        memset(buf, 0, sizeof(buf));
        ssize_t r = read(klog_fd, buf, sizeof(buf));

        if(r < 0){
            printf("read failed: %s\n", strerror(errno));
            close(klog_fd);
            return 1;
        }

        buf[r] = '\0';
        printf("%s", buf);
    }

    close(klog_fd);

    return 0;
}
