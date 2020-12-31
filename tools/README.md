# Tools

klog will read from `/dev/klog` for incoming `kprintf` messages. It depends on
`atm_diagnostic_config=0x20000000` being present in XNU's boot arguments.
