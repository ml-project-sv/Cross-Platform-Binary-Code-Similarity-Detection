"""
extract_acfg_angr.py  (architecture-aware: x86 / ARM / MIPS)
Extract ACFGs from a linked shared object using ANGR ONLY, in the dataset's
JSON-lines format. FEATURE ORDER (consistent across ALL arches/files):
  [0] string consts  [1] numeric consts  [2] transfer  [3] calls
  [4] instructions   [5] arithmetic      [6] offspring (out-degree)
"""
import sys, json, logging
for n in ['angr', 'cle', 'pyvex', 'claripy']:
    logging.getLogger(n).setLevel(logging.CRITICAL)
import angr, capstone
from capstone import x86 as cs_x86, arm as cs_arm, mips as cs_mips

ARITH = {
    'add','sub','mul','imul','div','idiv','inc','dec','neg','adc','sbb',
    'and','or','xor','not','shl','shr','sar','sal','rol','ror','lea',
    'adds','subs','rsb','mla','mls','umull','smull','orr','eor','bic',
    'lsl','lsr','asr','mvn','sbc',
    'addu','addiu','subu','mult','multu','dmult','ddiv','divu','nor',
    'sll','srl','sra','sllv','srlv','srav','andi','ori','xori','mflo','mfhi',
}

def imm_mem_consts(arch_name):
    a = arch_name.upper()
    if a.startswith('X86') or 'AMD64' in a:
        return cs_x86.X86_OP_IMM, cs_x86.X86_OP_MEM
    if a.startswith('ARM') or a.startswith('AARCH'):
        return cs_arm.ARM_OP_IMM, cs_arm.ARM_OP_MEM
    if a.startswith('MIPS'):
        return cs_mips.MIPS_OP_IMM, cs_mips.MIPS_OP_MEM
    return None, None

def points_to_string(proj, addr):
    try:
        sec = proj.loader.find_section_containing(addr)
        if sec is None or not sec.is_readable or sec.is_writable:
            return False
        b = proj.loader.memory.load(addr, 1)
        return 32 <= b[0] < 127
    except Exception:
        return False

def block_features(proj, blk, out_degree, IMM, MEM):
    insns = blk.capstone.insns

    n_instr = len(insns); n_call=n_xfer=n_arith=n_num=n_str=0

    for ci in insns:
        ix = ci.insn; gr = set(ix.groups)

        if capstone.CS_GRP_CALL in gr: n_call += 1

        if gr & {capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL,
                 capstone.CS_GRP_RET, capstone.CS_GRP_BRANCH_RELATIVE}: n_xfer += 1

        if ix.mnemonic.split('.')[0] in ARITH: n_arith += 1

        try:
            for op in ix.operands:
                if IMM is not None and op.type == IMM:
                    n_num += 1
                    if points_to_string(proj, op.imm): n_str += 1
                elif MEM is not None and op.type == MEM:
                    disp = getattr(op.mem, 'disp', 0)
                    if disp and points_to_string(proj, disp): n_str += 1
        except Exception:
            pass
    
    return [float(n_str), float(n_num), float(n_xfer), float(n_call),
            float(n_instr), float(n_arith), float(out_degree)]

def extract(so_path, src_tag, out_path):
    proj = angr.Project(so_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)

    # add = cfg.kb.functions["add"]
    # print(add.graph.nodes)

    # for node in add.graph.nodes:
    #     print(node.addr)

    # nodes = sorted(add.graph.nodes(), key=lambda n: n.addr)
    # addr2i = {n.addr: i for i, n in enumerate(nodes)}
    # print(addr2i)

    # for u, v in add.graph.edges():
    #     print(u, v)


    IMM, MEM = imm_mem_consts(proj.arch.name)

    SKIP = {'_init','_fini','frame_dummy','register_tm_clones',
            'deregister_tm_clones','__do_global_ctors_aux','__do_global_dtors_aux',
            'atexit','__libc_csu_init','__libc_csu_fini','call_weak_fn','abort',
            '__gmon_start__'}

    n_written = 0
    with open(out_path, 'w') as out:
        for func in cfg.kb.functions.values():

            if func.is_plt or func.is_simprocedure or not func.name: continue
            if func.name.startswith('sub_') or func.size <= 0: continue
            if func.name in SKIP or func.name.startswith('__x86') \
                    or func.name.startswith('__gmon') \
                    or func.name.startswith('_GLOBAL') \
                    or func.name.startswith('__mips'): continue
            
            nodes = sorted(func.graph.nodes(), key=lambda n: n.addr)
            if not nodes: continue
            addr2i = {n.addr: i for i, n in enumerate(nodes)}
            succs = [[] for _ in nodes]
            
            for u, v in func.graph.edges():
                if u.addr in addr2i and v.addr in addr2i:
                    succs[addr2i[u.addr]].append(addr2i[v.addr])
            feats, ok = [], True
            
            for i, bn in enumerate(nodes):
                try:
                    blk = proj.factory.block(bn.addr, size=bn.size)
                    feats.append(block_features(proj, blk, len(succs[i]), IMM, MEM))
                except Exception:
                    ok = False; break
            if not ok: continue
            
            out.write(json.dumps({"src": f"{src_tag}/{func.name}",
                "n_num": len(nodes), "succs": succs, "features": feats,
                "fname": func.name}) + "\n")
            
            n_written += 1

    return proj.arch.name, n_written

if __name__ == '__main__':
    so_path, src_tag, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    arch, n = extract(so_path, src_tag, out_path)
    _ = extract(so_path, src_tag, out_path)
    
    print(f"{out_path}: arch={arch}, wrote {n} functions")
