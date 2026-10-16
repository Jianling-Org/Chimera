#!/bin/sh
set -eu
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo 'usage: build.sh <absolute-native-kernel.o> <absolute-forward-kernel.o> <absolute-reverse-kernel.o> [samples]' >&2
    exit 2
fi
native_kernel=$1
forward_kernel=$2
reverse_kernel=$3
samples=${4:-50}
case "$samples" in 3|50) ;; *) echo 'samples must be 3 (pilot) or 50 (full)' >&2; exit 2 ;; esac
for object in "$native_kernel" "$forward_kernel" "$reverse_kernel"; do
    case "$object" in /*) ;; *) echo "object path must be absolute: $object" >&2; exit 2 ;; esac
    test -f "$object" || { echo "object not found: $object" >&2; exit 2; }
done
cd "$(dirname "$0")"
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize -Wall -Wextra -DBENCH_SAMPLES="$samples" -DBENCH_NATIVE=1 -DSOURCE_VLENB=32 -DTARGET_VLENB=32 -DCPU_FIRST=0 -c translated.c -o native256-driver.o
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize -Wall -Wextra -DBENCH_SAMPLES="$samples" -DBENCH_NATIVE=1 -DSOURCE_VLENB=128 -DTARGET_VLENB=128 -DCPU_FIRST=8 -c translated.c -o native1024-driver.o
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize -Wall -Wextra -DBENCH_SAMPLES="$samples" -DSOURCE_VLENB=128 -DTARGET_VLENB=32 -DCPU_FIRST=0 -c translated.c -o forward-driver.o
clang -O3 -march=rv64gc -mabi=lp64d -fopenmp -fno-vectorize -fno-slp-vectorize -Wall -Wextra -DBENCH_SAMPLES="$samples" -DSOURCE_VLENB=32 -DTARGET_VLENB=128 -DCPU_FIRST=8 -c translated.c -o reverse-driver.o
clang -march=rv64gc -mabi=lp64d -fopenmp native256-driver.o "$native_kernel" -lm -o bench-native256
clang -march=rv64gc -mabi=lp64d -fopenmp native1024-driver.o "$native_kernel" -lm -o bench-native1024
clang -march=rv64gc -mabi=lp64d -fopenmp forward-driver.o "$forward_kernel" -lm -o bench-forward
clang -march=rv64gc -mabi=lp64d -fopenmp reverse-driver.o "$reverse_kernel" -lm -o bench-reverse
sha256sum translated.c native256-driver.o native1024-driver.o forward-driver.o reverse-driver.o bench-native256 bench-native1024 bench-forward bench-reverse
