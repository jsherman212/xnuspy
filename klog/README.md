# klog

klog will read from `/dev/klog` for incoming `kprintf` and `IOLog` messages.
It depends on `atm_diagnostic_config=0x20000000` being present in
XNU's boot arguments.

Recommended usage: `stdbuf -o0 ./klog | grep <thing>`

Run `make` in this directory to build `klog`. `make upload` will
upload it to your device, but you may have to swap out the port number.
