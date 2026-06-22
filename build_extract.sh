#!/bin/bash
# build_extract.sh  SRCDIR  CC  TAG  OPT  VERSION  OUTDIR
# Compiles (near-)full OpenSSL for one (arch,opt), links a PIC .so, extracts ACFGs.
SRCDIR="$1"; CC="$2"; TAG="$3"; OPT="$4"; VER="$5"; OUT="$6"
cd "$SRCDIR"
INC="-Iinclude -Icrypto -I."
SRCS=$(find crypto ssl -name '*.c' | grep -vE 'test|speed|demo|/asm/|/perlasm/|jpake|store|enginetest')
OBJ=/tmp/o_${TAG}_${OPT}; mkdir -p $OBJ; rm -f $OBJ/*.o
ok=0
for c in $SRCS; do
  $CC -$OPT -fPIC $INC -Icrypto/$(basename $(dirname $c)) -DOPENSSL_NO_ASM \
      -c "$c" -o "$OBJ/$(basename $c .c).o" 2>/dev/null && ok=$((ok+1))
done
SO=/tmp/${VER}-${TAG}-${OPT}.so
$CC -shared -fPIC -Wl,--allow-multiple-definition -o $SO $OBJ/*.o 2>/dev/null
rm -rf $OBJ
echo "built $TAG $OPT: $ok objs, $(ls -la $SO|awk '{print $5}') bytes"
python3 /home/claude/extract_acfg_angr.py "$SO" "${VER}-${TAG}-${OPT}" \
    "$OUT/${VER}-${TAG}-${OPT}.json" 2>/dev/null
rm -f $SO
