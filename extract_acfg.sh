extract_acfg() {
    libname=$1
    mkdir -p data_acfg/${libname}_acfg

    for so_dir in data_compiled/${libname}_so/*; do
        fname=$(basename "$so_dir")
        src_tag=${fname%.so}
        out_path=data_acfg/${libname}_acfg/$src_tag.json
        python3 extract_acfg_angr.py "$so_dir" "$src_tag" "$out_path"
        echo "$out_path done!"
    done
}

# extract_acfg "openssl"
# extract_acfg "zlib"
extract_acfg "sqlite3"


