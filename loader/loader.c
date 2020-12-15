#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libusb-1.0/libusb.h>

static int pongo_send_command(libusb_device_handle *pongo_device,
        const char *command){
    size_t command_len = 1;

    if(command)
        command_len += strlen(command);

    return libusb_control_transfer(pongo_device, 0x21, 3, 0, 0,
            (unsigned char *)command, command_len, 0);
}

static int pongo_init_bulk_upload(libusb_device_handle *pongo_device){
    return libusb_control_transfer(pongo_device, 0x21, 1, 0, 0, NULL, 0, 0);
}

static int pongo_discard_bulk_upload(libusb_device_handle *pongo_device){
    return libusb_control_transfer(pongo_device, 0x21, 2, 0, 0, NULL, 0, 0);
}

static int pongo_do_bulk_upload(libusb_device_handle *pongo_device,
        void *data, size_t len){
    return libusb_bulk_transfer(pongo_device, 2, data, len, NULL, 0);
}

static int pongo_get_stdout(libusb_device_handle *pongo_device, char *outbuf){
    return libusb_control_transfer(pongo_device, 0xa1, 1, 0, 0,
            (unsigned char *)outbuf, 512, 0);
}

static int hotplug_callback(libusb_context *ctx, libusb_device *device,
        libusb_hotplug_event event, void *user_data){
    if(event != LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED)
        return 0;

    libusb_device_handle **pongo_device = (libusb_device_handle **)user_data;
    int err = libusb_open(device, pongo_device);
    
    if(err){
        printf("Couldn't open pongoOS device: %s\n", libusb_error_name(err));
        libusb_exit(NULL);
        exit(1);
    }

    return 0;
}

int main(int argc, char **argv, const char **envp){
    if(argc < 2){
        printf("usage: loader <pongo module>\n");
        return 1;
    }

    int err = libusb_init(NULL);

    if(err < 0){
        printf("libusb_init failed: %d\n", err);
        return 1;
    }

    printf("Waiting for pongoOS device...\n");

    libusb_hotplug_callback_handle cbh = 0;
    libusb_device_handle *pongo_device = NULL;

    err = libusb_hotplug_register_callback(NULL, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
            LIBUSB_HOTPLUG_ENUMERATE, 0x5ac, 0x4141, LIBUSB_HOTPLUG_MATCH_ANY,
            hotplug_callback, &pongo_device, &cbh);

    if(err < 0){
        printf("libusb_hotplug_register_callback: %s\n", libusb_error_name(err));
        return 1;
    }

    while(!pongo_device)
        libusb_handle_events_completed(NULL, NULL);

    libusb_hotplug_deregister_callback(NULL, cbh);

    printf("Got pongoOS device\n");

    err = libusb_claim_interface(pongo_device, 0);

    if(err < 0){
        printf("libusb_claim_interface: %s\n", libusb_error_name(err));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    char *module_path = argv[1];
    struct stat st = {0};
    
    if(stat(module_path, &st)){
        printf("Problem stat'ing '%s': %s\n", module_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    int module_fd = open(module_path, O_RDONLY);

    if(module_fd < 0){
        printf("Problem open'ing '%s': %s\n", module_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    size_t module_size = st.st_size;
    printf("Module size %#lx\n", module_size);

    void *module_data = mmap(NULL, module_size, PROT_READ, MAP_PRIVATE,
            module_fd, 0);

    if(module_data == MAP_FAILED){
        printf("Problem mmap'ing '%s': %s\n", module_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    const char *xnuspy_ctl_path = "./module/el1/xnuspy_ctl/xnuspy_ctl";

    memset(&st, 0, sizeof(st));

    if(stat(xnuspy_ctl_path, &st)){
        printf("Problem stat'ing '%s': %s\n", xnuspy_ctl_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    size_t xnuspy_ctl_imgsz = st.st_size;
    printf("xnuspy_ctl image size %#zx\n", xnuspy_ctl_imgsz);

    int xnuspy_ctl_fd = open(xnuspy_ctl_path, O_RDONLY);

    if(xnuspy_ctl_fd == -1){
        printf("Problem open'ing '%s': %s\n", xnuspy_ctl_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    void *xnuspy_ctl_imgdata = mmap(NULL, xnuspy_ctl_imgsz, PROT_READ,
            MAP_PRIVATE, xnuspy_ctl_fd, 0);

    if(xnuspy_ctl_imgdata == MAP_FAILED){
        printf("Problem mmap'ing '%s': %s\n", xnuspy_ctl_path, strerror(errno));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_init_bulk_upload(pongo_device);

    if(err < 0){
        printf("pongo_init_bulk_upload: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_do_bulk_upload(pongo_device, module_data, module_size);

    if(err < 0){
        printf("pongo_do_bulk_upload (module): %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    err = pongo_send_command(pongo_device, "modload\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }
    
    munmap(module_data, module_size);

    usleep(800 * 1000);

    /* If you edit this, you must make sure not to delete
     * 'use_contiguous_hint=0'
     */
    err = pongo_send_command(pongo_device, "xargs rootdev=md0"
            " use_contiguous_hint=0 msgbuf=0x3c000 -show_pointers\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }
    
    munmap(module_data, module_size);

    usleep(200 * 1000);

    err = pongo_send_command(pongo_device, "xnuspy-getkernelv\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    /* we may have had to pwn SEPROM, so wait a bit longer before we continue */
    /* sleep(4); */

    /* send the compiled xnuspy_ctl syscall */
    err = pongo_init_bulk_upload(pongo_device);

    if(err < 0){
        printf("pongo_init_bulk_upload: %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    usleep(800 * 1000);

    err = pongo_do_bulk_upload(pongo_device, xnuspy_ctl_imgdata,
            xnuspy_ctl_imgsz);

    if(err < 0){
        printf("pongo_do_bulk_upload (xnuspy_ctl): %s\n", libusb_error_name(err));
        munmap(module_data, module_size);
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

    sleep(2);

/* #if 0 */
    err = pongo_send_command(pongo_device, "xnuspy-prep\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }

/* #if 0 */
    usleep(800 * 1000);

    err = pongo_send_command(pongo_device, "bootx\n");

    if(err < 0){
        printf("pongo_send_command: %s\n", libusb_error_name(err));
        libusb_release_interface(pongo_device, 0);
        libusb_close(pongo_device);
        libusb_exit(NULL);
        return 1;
    }
/* #endif */

    libusb_release_interface(pongo_device, 0);
    libusb_close(pongo_device);
    libusb_exit(NULL);

    return 0;
}
