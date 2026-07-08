OPTS=("O0" "O1" "O2" "O3")

declare -A CMPS=(
    [x86]="gcc -m32"
    [arm32]="arm-linux-gnueabi-gcc"
    [mips32]="mips-linux-gnu-gcc"
)

build_openssl() {
    SRC="../data_source/openssl-OpenSSL_1_0_1u"
    SRCS=$(find $SRC -name "*.c")

    for arch in "${!CMPS[@]}"; do
        cc="${CMPS[$arch]}"
        for opt in "${OPTS[@]}"; do
            # create directory for each (arch, opt) pair 
            OBJ="openssl_1_0_1u_obj/openssl_1_0_1u-obj-${arch}-${opt}"
            mkdir -p $OBJ openssl_1_0_1u_so

            # header file include command for compiler
            INC="-I$SRC/include -I$SRC/crypto -I$SRC"
            
            # compile c source files into .o object files
            for c in $SRCS; do
                $cc -$opt -DOPENSSL_NO_ASM -fPIC $INC \
                    -c "$c" \
                    -o "${OBJ}/openssl_1_0_1u-$arch-$opt-$(basename "${c%.c}").o" 2>/dev/null || true
            done

            # link .o object files into .so library
            $cc -shared -fPIC -Wl,--allow-multiple-definition \
                -o openssl_1_0_1u_so/openssl_1_0_1u-$arch-$opt.so $OBJ/*.o 2>/dev/null || true

            echo "openssl_1_0_1u-$arch-$opt.so done!"
        done
    done
}


build_zlib() {
    SRC="../data_source/zlib-1.3.1"
    SRCS=$(find $SRC -name "*.c")

    for arch in "${!CMPS[@]}"; do
        cc="${CMPS[$arch]}"
        for opt in "${OPTS[@]}"; do
            # create directory for each (arch, opt) pair 
            OBJ="zlib_obj/zlib-1.3.1-obj-${arch}-${opt}"
            mkdir -p $OBJ zlib_so

            INC="-I$SRC"

            # compile c source files into .o object files
            for c in $SRCS; do
                $cc -$opt -fPIC $INC \
                    -c "$c" \
                    -o "${OBJ}/zlib-1.3.1-$arch-$opt-$(basename "${c%.c}").o" 2>/dev/null || true
            done

            # link .o object files into .so library
            $cc -shared -fPIC -Wl,--allow-multiple-definition \
                -o zlib_so/zlib-1.3.1-$arch-$opt.so $OBJ/*.o 2>/dev/null || true

            echo "zlib-1.3.1-$arch-$opt.so done!"
        done
    done
}

build_sqlite3() {
    SRC="../data_source/sqlite-amalgamation-3530300"

    for arch in "${!CMPS[@]}"; do
        cc="${CMPS[$arch]}"
        for opt in "${OPTS[@]}"; do
            # create directory for each (arch, opt) pair 
            OBJ="sqlite3_obj/sqlite-amalgamation-3530300-obj-${arch}-${opt}"
            mkdir -p $OBJ sqlite3_so

            INC="-I$SRC"

            # compile only sqlite3.c
            c=$SRC/sqlite3.c

            # compile c source files into .o object files
            $cc -$opt -fPIC $INC \
                -c $c \
                -o "${OBJ}/sqlite-amalgamation-3530300-$arch-$opt-$(basename "${c%.c}").o" #2>/dev/null || true

            # link .o object files into .so library
            $cc -shared -fPIC -Wl,--allow-multiple-definition \
                -o sqlite3_so/sqlite-amalgamation-3530300-$arch-$opt.so $OBJ/*.o 2>/dev/null || true

            echo "sqlite-amalgamation-3530300-$arch-$opt.so done!"
        done
    done
}


build_openssl
# build_zlib
# build_sqlite3

# # check number of exported functions in openssl .so files
# for f in openssl_so/*.so; do   
#     echo "$f: $(nm -D "$f" 2>/dev/null | grep ' T ' | wc -l) functions, $(stat -c%s "$f") bytes";
# done

# # check number of exported functions in zlib .so files
# for f in zlib_so/*.so; do   
#     echo "$f: $(nm -D "$f" 2>/dev/null | grep ' T ' | wc -l) functions, $(stat -c%s "$f") bytes";
# done

