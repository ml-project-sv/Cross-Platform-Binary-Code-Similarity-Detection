#!/bin/bash
# Build every remaining combo to reach the full 2-version x 3-arch x 4-opt grid.
OUT=/home/claude/data_angr_big/acfgSSL_angr_7
declare -A CC=( [x86]="gcc -m32" [arm]="arm-linux-gnueabi-gcc" [mips]="mips-linux-gnu-gcc" )
for VER in 1.0.1f 1.0.1u; do
  SRC=/home/claude/openssl-OpenSSL_${VER//./_}
  for ARCH in x86 arm mips; do
    for OPT in O0 O1 O2 O3; do
      F="$OUT/openssl-$VER-$ARCH-$OPT.json"
      [ -s "$F" ] && { echo "skip $VER $ARCH $OPT (exists)"; continue; }
      bash /home/claude/build_extract.sh "$SRC" "${CC[$ARCH]}" "$ARCH" "$OPT" "openssl-$VER" "$OUT"
    done
  done
done
python3 /home/claude/prep_split_big.py
