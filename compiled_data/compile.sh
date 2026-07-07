SRC="../source_data/openssl-OpenSSL_1_0_1f"

SRCS=$(find $SRC -name "*.c")

OPTS=("O0" "O1" "O2" "O3")

declare -A CMPS=(
    [x86]="gcc -m32"
    [arm32]="arm-linux-gnueabi-gcc"
    [mips32]="mips-linux-gnu-gcc"
)

for arch in "${!CMPS[@]}"; do
    cc="${CMPS[$arch]}"
    for opt in "${OPTS[@]}"; do
        # create directory for each (arch, opt) pair 
        OBJ="openssl_1_0_1f-obj-${arch}-${opt}"
        mkdir -p $OBJ

        # header file include command for compiler
        INC="-I$SRC/include -I$SRC/crypto -I$SRC"
        
        # compile c source files into .o object files
        for c in $SRCS; do
            $cc -$opt -DOPENSSL_NO_ASM -fPIC $INC \
                -c "$c" \
                -o "${OBJ}/openssl_1_0_1f-$arch-$opt-$(basename "${c%.c}").o" 2>/dev/null || true
        done

        # link .o object files into .so library
        $cc -shared -fPIC -Wl,--allow-multiple-definition \
            -o openssl_1_0_1f-$arch-$opt.so $OBJ/*.o 2>/dev/null || true

        echo "openssl_1_0_1f-$arch-$opt.so done!"
    done
done


