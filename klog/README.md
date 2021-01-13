# klog

klog will read from `/dev/klog` for incoming `kprintf` messages. It depends on
`atm_diagnostic_config=0x20000000` being present in XNU's boot arguments.
Recommended usage: `stdbuf -o0 ./klog | grep <thing>`

To compile (on device):

```
clang-10 -isysroot <your sdk> klog.c -o klog
ldid -Sent.xml -P ./klog
```

You'll find `ent.xml` inside `example/`.
