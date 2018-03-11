# !bin/bash
set -o errexit

CRETE_BINARY_DIR=$1
CRETE_TARGET_VD=$2

./make_op_helper_bc.sh $2

ln -sf `pwd`/bc_crete_ops.bc $CRETE_BINARY_DIR/bin/bc_crete_ops.bc

cd i386-softmmu \
	&& ln -sf `pwd`/bc_target_i386_helpers.bc $CRETE_BINARY_DIR/bin/crete-qemu-2.3-op-helper-i386.bc \
	&& ln -sf `pwd`/crete-llvm-translator-i386 $CRETE_BINARY_DIR/bin/crete-llvm-translator-qemu-2.3-i386

cd ../x86_64-softmmu/ \
        && ln -sf `pwd`/bc_target_x86_64_helpers.bc $CRETE_BINARY_DIR/bin/crete-qemu-2.3-op-helper-x86_64.bc \
	&& ln -sf `pwd`/crete-llvm-translator-x86_64 $CRETE_BINARY_DIR/bin/crete-llvm-translator-qemu-2.3-x86_64
