# !bin/bash

### Note:
# 1. run this script under root folder of qemu source tree
# 2. use -O0 -fno-inline for debugging

echo "  LLVMCC    bc_vd_e1000.bc" && clang-3.4      \
    -c                                              \
    -O0 -fno-inline                                 \
    -I.                                             \
    -Itcg                                           \
    -Itcg/tci                                       \
    -Ilinux-headers                                 \
    -Iinclude                                       \
    -Itests                                         \
    -Ihw/net                                        \
    -I/usr/include/pixman-1                         \
    -I/usr/include/p11-kit-1                        \
    -I/usr/include/libpng12                         \
    -I/usr/include/glib-2.0                         \
    -I/usr/lib/x86_64-linux-gnu/glib-2.0/include    \
    -DPIE -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_FORTIFY_SOURCE=2 \
    -emit-llvm                                      \
    hw/net/bc_e1000.c                               \
    -o bc_vd_e1000.bc

echo "  LLVMCC    bc_vd_eepro100.bc" && clang-3.4   \
    -c                                              \
    -O0 -fno-inline                                 \
    -I.                                             \
    -Ihw/net                                        \
    -Itcg                                           \
    -Itcg/tci                                       \
    -Itests                                         \
    -Iinclude                                       \
    -Ilinux-headers                                 \
    -I/usr/include/pixman-1                         \
    -I/usr/include/p11-kit-1                        \
    -I/usr/include/libpng12                         \
    -I/usr/include/glib-2.0                         \
    -I/usr/lib/x86_64-linux-gnu/glib-2.0/include    \
    -DPIE -D_GNU_SOURCE -D_FORTIFY_SOURCE=2         \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE      \
    -U_FORTIFY_SOURCE                               \
    -fPIE -fno-strict-aliasing -fno-common -fstack-protector-all \
    -emit-llvm                                      \
    hw/net/bc_eepro100.c                            \
    -o bc_vd_eepro100.bc

echo "  LLVMCC    bc_vd_ne2000.bc" && clang-3.4     \
    -c                                              \
    -O0 -fno-inline                                 \
    -I.                                             \
    -Ihw/net                                        \
    -Itcg                                           \
    -Itcg/tci                                       \
    -Itests                                         \
    -Iinclude                                       \
    -Ilinux-headers                                 \
    -I/usr/include/pixman-1                         \
    -I/usr/include/p11-kit-1                        \
    -I/usr/include/libpng12                         \
    -I/usr/include/glib-2.0                         \
    -I/usr/lib/x86_64-linux-gnu/glib-2.0/include    \
    -DPIE -D_GNU_SOURCE -D_FORTIFY_SOURCE=2         \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE      \
    -U_FORTIFY_SOURCE                               \
    -fPIE -fno-strict-aliasing -fno-common -fstack-protector-all \
    -emit-llvm                                      \
    hw/net/bc_ne2000.c                              \
    -o bc_vd_ne2000.bc

### old flags
# -m64 -pthread
# -MMD -MP -MT hw/net/ne2000.o -MF hw/net/ne2000.d -O2

# -DPIE -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DHAS_AUDIO -DHAS_AUDIO_CHOICE -DTARGET_PHYS_ADDR_BITS=64 \
    # -Wno-invalid-noreturn
# -m64
# -MMD -MP -MT -march=native  \