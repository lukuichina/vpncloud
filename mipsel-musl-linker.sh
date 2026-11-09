#!/bin/bash
# Wrapper that calls the musl MIPS gcc for static linking.
# Rust passes -Wl,-Bdynamic before -lgcc_s -lc which overrides -static,
# and -lgcc_s can't be found in static mode.
# We strip -Wl,-Bdynamic and -lgcc_s, and insert -lgcc_eh BEFORE -lc
# so libgcc_eh.a's pthread_once resolves against libc.a.
new_args=()
for arg in "$@"; do
    if [ "$arg" = "-Wl,-Bdynamic" ]; then continue; fi
    if [ "$arg" = "-lgcc_s" ]; then continue; fi
    if [ "$arg" = "-lc" ]; then
        new_args+=("-lgcc_eh" "-lc")
        continue
    fi
    new_args+=("$arg")
done
exec /opt/musl/mipsel_le/mipsel-linux-muslsf-cross/bin/mipsel-linux-muslsf-gcc -static "${new_args[@]}"
