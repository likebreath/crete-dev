# !/bin/sh

## Usage example: add to /etc/rc.local
## "/path/to/auto_replay.sh /path/to/crete-out/e1000.xml e1000"

set -e

INPUT_DIR=$1
TARGET_MODULE=$2
CRETE_BIN_DIR="/home/test/guest-build/bin/"

setup_replay()
{
    # printf "dmesg -C\n"
    # printf "insmod /home/test/guest/kernel-modules/crete-intrinsics-replay/crete-intrinsics-replay.ko\n"
    # printf "insmod /home/test/guest/kernel-modules/kprobe_kernel_api/crete_kprobe_kernel_api.ko target_module=\"$TARGET_MODULE\"\n"
    # printf "rmmod $TARGET_MODULE\n"

    dmesg -C
    insmod /home/test/guest/kernel-modules/crete-intrinsics-replay/crete-intrinsics-replay.ko
    insmod /home/test/guest/kernel-modules/kprobe_kernel_api/crete_kprobe_kernel_api.ko target_module="$TARGET_MODULE"
    rmmod $TARGET_MODULE
}

main()
{
   if [ -z  $INPUT_DIR ]; then
        printf "Input directory is invalid ...\n"
        exit 0
    fi

   AUTO_REPLAY_DIR=$(readlink -m $INPUT_DIR)

   printf "Input direcotry: $AUTO_REPLAY_DIR\n"

   if [ ! -d  $AUTO_REPLAY_DIR ]; then
       printf "\'$AUTO_REPLAY_DIR\' does not exists\n"
       exit 0
   fi

   REPLAY_CMD="-a $AUTO_REPLAY_DIR"
   # printf "$CRETE_BIN_DIR/crete-tc-replay $REPLAY_CMD\n"

   setup_replay
   $CRETE_BIN_DIR/crete-tc-replay $REPLAY_CMD
}

main
