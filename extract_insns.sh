extract_insns() {
    libname=$1
    mkdir -p data_insns/${libname}_insns

    for so_dir in data_compiled/${libname}_so/*; do
        fname=$(basename "$so_dir")
        src_tag=${fname%.so}
        out_path=data_insns/${libname}_insns/$src_tag.json
        python3 extract_insns_angr.py "$so_dir" "$src_tag" "$out_path"
        echo "$out_path done!"
    done
}

# extract_insns "openssl"
# extract_insns "zlib"
extract_insns "sqlite3"


