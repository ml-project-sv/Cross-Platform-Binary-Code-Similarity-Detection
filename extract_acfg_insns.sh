extract_acfg_insns() {
    libname=$1
    mkdir -p data_acfg_insns/${libname}_acfg_angr

    for so_dir in data_compiled/${libname}_so/*; do
        fname=$(basename "$so_dir")
        src_tag=${fname%.so}
        out_path=data_acfg_insns/${libname}_acfg_angr/$src_tag.json
        python3 extract_acfg_insns_angr.py "$so_dir" "$src_tag" "$out_path"
        echo "$out_path done!"
    done
}

extract_acfg_insns "zlib"
extract_acfg_insns "sqlite3"
extract_acfg_insns "openssl_1_0_1u"
extract_acfg_insns "openssl_1_0_1f"
