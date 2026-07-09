extract_insns_rich() {
    libname=$1
    mkdir -p data_insns_rich/${libname}_insns_rich

    for so_dir in data_compiled/${libname}_so/*; do
        fname=$(basename "$so_dir")
        src_tag=${fname%.so}
        out_path=data_insns_rich/${libname}_insns_rich/$src_tag.json
        python3 extract_insns_rich_angr.py "$so_dir" "$src_tag" "$out_path"
        echo "$out_path done!"
    done
}

extract_insns_rich "zlib"
extract_insns_rich "sqlite3"
extract_insns_rich "openssl_1_0_1f"
extract_insns_rich "openssl_1_0_1u"

