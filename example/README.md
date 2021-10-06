# Examples
Porting these to other kernels is just a matter of swapping out offsets.

Run `make` in this directory to build all of them. `make upload` will
upload them to your device, but you may have to swap out the port number.

### open1_hook
This hooks `open1` and logs a message about the file a process just tried
to open, while at the same time preventing everyone from `open`'ing
`/var/mobile/testfile.txt`.

Some offsets I already have for `open1`:

```
iPhone X 13.3.1:        0xfffffff007d70534
iPhone X 15.0:          0xfffffff007d574f4
iPhone 8 13.6.1:        0xfffffff007d99c1c
iPhone 8 14.6:          0xfffffff007c4c8c4
iPhone 8 14.8:          0xfffffff007c4c930
iPhone 7 14.1:          0xfffffff00730aa64
iPhone 7 14.5:          0xfffffff00733b960
iPhone 7 15.0:          0xfffffff00736addc
iPhone SE (2016) 14.3:  0xfffffff0072da190
iPhone SE (2016) 14.5:  0xfffffff0072fd3dc
```

### user_client_monitor
This hooks `is_io_service_open_extended` and logs a descriptive message every
time any process opens a new IOKit user client.

Some offsets I already have for this:

```
iPhone X 13.3.1:
    getClassName: 0xfffffff0080bf600
    is_io_service_open_extended: 0xfffffff008168d28

iPhone X 15.0:
    getClassName: 0xfffffff0080e8ba0
    is_io_service_open_extended: 0xfffffff0081c1580

iPhone 8 13.6.1:
    getClassName: 0xfffffff0080ec9a8
    is_io_service_open_extended: 0xfffffff0081994dc

iPhone 8 14.6:
    getClassName: 0xfffffff007fbd108
    is_io_service_open_extended: 0xfffffff008085dd0

iPhone 8 14.8:
    getClassName: 0xfffffff007fbd400
    is_io_service_open_extended: 0xfffffff0080861a0

iPhone 7 14.1:
    getClassName: 0xfffffff00765be54
    is_io_service_open_extended: 0xfffffff00770d114

iPhone 7 14.5:
    getClassName: 0xfffffff00769130c
    is_io_service_open_extended: 0xfffffff0077473a8

iPhone 7 15.0:
    getClassName: 0xfffffff0076dcac4
    is_io_service_open_extended: 0xfffffff0077a1f2c

iPhone SE (2016) 14.3:
    getClassName: 0xfffffff00762e3e4
    is_io_service_open_extended: 0xfffffff0076e3104

iPhone SE (2016) 14.5:
    getClassName: 0xfffffff007652c80
    is_io_service_open_extended: 0xfffffff007708dac
```

### kernel_thread
This hooks `hookme`, invokes `xnuspy_ctl` to call it, starts up a kernel
thread, and registers a death callback.

### kaddr_of_port
This uses `XNUSPY_KREAD` to determine the kernel addres of a userspace
Mach port handle.

Some offsets I already have for `offsetof(struct task, itk_space)`:

```
iPhone 8 13.6.1: 0x320
iPhone X 13.3.1: 0x320
iPhone 7 14.1:   0x330
```

### shmem
Demonstrates kernel-user shared data synchronization with shared memory
returned by `mkshmem_ktou`.
