# Examples
Porting these to other kernels is just a matter of swapping out offsets.

### open1_hook
This hooks `open1` and logs a message about the file a process just tried
to open, while at the same time preventing everyone from `open`'ing
`/var/mobile/testfile.txt`.

Some offsets I already have for `open1`:

```
iPhone X 13.3.1:        0xfffffff007d70534
iPhone 8 13.6.1:        0xfffffff007d99c1c
iPhone 7 14.1:          0xfffffff00730aa64
iPhone SE (2016) 14.3:  0xfffffff0072da190
```

### user_client_monitor
This hooks `is_io_service_open_extended` and logs a descriptive message every
time any process opens a new IOKit user client.

Some offsets I already have for this:

```
iPhone X 13.3.1:
    getClassName: 0xfffffff0080bf600
    is_io_service_open_extended: 0xfffffff008168d28

iPhone 8 13.6.1:
    getClassName: 0xfffffff0080ec9a8
    is_io_service_open_extended: 0xfffffff0081994dc

iPhone 7 14.1:
    getClassName: 0xfffffff00765be54
    is_io_service_open_extended: 0xfffffff00770d114

iPhone SE (2016) 14.3:
    getClassName: 0xfffffff00762e3e4
    is_io_service_open_extended: 0xfffffff0076e3104
```

### kernel_thread
This hooks `hookme`, invokes `xnuspy_ctl` to call it, starts up a kernel
thread, and registers a death callback.

### Compiling (on device)
```
clang-10 -Wno-deprecated-declarations -isysroot <your sdk> open1_hook.c -o open1_hook
ldid -Sent.xml -P ./open1_hook
```

```
clang-10 -Wno-deprecated-declarations -isysroot <your sdk> user_client_monitor.c -o user_client_monitor
ldid -Sent.xml -P ./user_client_monitor
```

```
clang-10 -Wno-deprecated-declarations -isysroot <your sdk> kernel_thread.c -o kernel_thread
ldid -Sent.xml -P ./kernel_thread
```
