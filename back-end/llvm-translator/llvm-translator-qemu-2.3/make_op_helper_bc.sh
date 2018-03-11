# !bin/bash
set -o errexit
CRETE_TARGET_VD=$1

if [ $CRETE_TARGET_VD == "E1000" ]; then
    target_vd_bc="bc_vd_e1000.bc"
elif [ $CRETE_TARGET_VD == "EEPRO100" ]; then
    target_vd_bc="bc_vd_eepro100.bc"
fi


echo "[Target-i386] GEN: bc_target_i386_helpers.bc" & \
    llvm-link-3.4 \
    tcg-llvm-offline/op_helpers/bc_target_i386_helpers.bc \
    tcg-llvm-offline/op_helpers/$target_vd_bc \
    -o i386-softmmu/bc_target_i386_helpers.bc

echo "[Target-x86_64] GEN: bc_target_x86_64_helpers.bc" &
    llvm-link-3.4 \
    tcg-llvm-offline/op_helpers/bc_target_x86_64_helpers.bc \
    tcg-llvm-offline/op_helpers/$target_vd_bc \
    -o x86_64-softmmu/bc_target_x86_64_helpers.bc

echo "GEN: bc_crete_ops.bc" & clang-3.4                \
    -c                                                 \
    -O0 -fno-inline                                    \
    -emit-llvm                                         \
    tcg-llvm-offline/bc_crete_ops.c                    \
    -o bc_crete_ops.bc


echo "GEN: bc_crete_ops_lli.bc" & clang-3.4            \
    -c                                                 \
    -O2                                                \
    -emit-llvm                                         \
    tcg-llvm-offline/bc_crete_ops_lli.cpp              \
    -o bc_crete_ops_lli.bc
