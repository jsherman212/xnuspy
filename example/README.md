# Examples
Every example is specific to the iPhone 8 running iOS 13.6.1. Porting these
to other kernels is just a matter of swapping out offsets.

### open1_hook
This hooks `open1` and prevents everyone from `open`'ing
`/var/mobile/testfile.txt`.

### user_client_monitor
This hooks `is_io_service_open_extended` and logs a descriptive message every
time any process opens a new IOKit user client.
