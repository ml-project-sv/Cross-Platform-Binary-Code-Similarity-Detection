import os, sys, json
import angr, capstone
import networkx as nx
from capstone import x86, arm, mips

# make angr save metadata in /tmp
# os.environ['TMPDIR'] = '/tmp'
# os.environ['ANGR_CACHE_DIR'] = '/tmp/angr_cache'
# os.makedirs('/tmp/angr_cache', exist_ok=True)

SKIP = {'_init', '_fini', 'frame_dummy', 'register_tm_clones', 'deregister_tm_clones', '__do_global_ctors_aux', '__do_global_dtors_aux', 'atexit', '__libc_csu_init', '__libc_csu_fini', 'call_weak_fn', 'abort', '__gmon_start__'}

# imm, mem and reg constants for given arch
def imm_mem_reg_for(arch):
    a = arch.upper()
    if a.startswith('X86')  or 'AMD64' in a: 
        return x86.X86_OP_IMM, x86.X86_OP_MEM, x86.X86_OP_REG
    
    if a.startswith('ARM')  or a.startswith('AARCH'): 
        return arm.ARM_OP_IMM, arm.ARM_OP_MEM, arm.ARM_OP_REG
    
    if a.startswith('MIPS'): 
        return mips.MIPS_OP_IMM, mips.MIPS_OP_MEM, mips.MIPS_OP_REG
    return None, None, None


# heuristic for checking if addr contains string
def is_string_at(proj, addr):
    try:
        # find section containing string
        sec = proj.loader.find_section_containing(addr)
        
        # section must be readable and not writable
        if sec is None or not sec.is_readable or sec.is_writable:
            return False

        # checking if character is printable
        return 0x20 <= proj.loader.memory.load(addr, 1)[0] < 0x80

    except Exception:
        return False


def normalize_insn(proj, ci, IMM, MEM, REG):
    ix = ci.insn
    mnem = ix.mnemonic.split('.')[0]
    parts = [mnem]

    is_transfer = bool(set(ix.groups) & {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP, capstone.CS_GRP_BRANCH_RELATIVE})
    
    for op in ix.operands:

        if REG is not None and op.type == REG:
            parts.append('reg')

        elif IMM is not None and op.type == IMM:
            parts.append('imm' if is_transfer else ('str' if is_string_at(proj, op.imm) else 'imm'))
        
        elif MEM is not None and op.type == MEM:
            parts.append('mem')

        else:
            parts.append('op')

    return ' '.join(parts)


def extract(so_path, src_tag, out_path):
    proj = angr.Project(so_path, auto_load_libs=False)
    cfg  = proj.analyses.CFGFast(normalize=True)
    
    n_funcs_written = 0
    IMM, MEM, REG = imm_mem_reg_for(proj.arch.name)

    with open(out_path, 'w') as out:

        for func in cfg.kb.functions.values():
            # check if function is valid
            if func.is_plt or func.is_simprocedure or not func.name: continue
            if func.name.startswith('sub_') or func.size <= 0: continue
            if func.name in SKIP or func.name.startswith(('__x86', '__gmon', '_GLOBAL', '__mips')): continue

            # extract nodes
            nodes = sorted(func.graph.nodes(), key=lambda n: n.addr)
            if not nodes: continue

            insns = []
            for bn in nodes:
                blk = proj.factory.block(bn.addr, size=bn.size)
                for ci in blk.capstone.insns:
                    insns.append(normalize_insn(proj, ci, IMM, MEM, REG))

            out.write(json.dumps({'src': f'{src_tag}/{func.name}', 'fname': func.name, 'n_num': len(nodes), 'insns': insns}) + '\n')
            n_funcs_written += 1

    return n_funcs_written

if __name__ == '__main__':
    so_path, src_tag, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    n_funcs_written = extract(so_path, src_tag, out_path)
    print(f'{n_funcs_written} extracted from {so_path}')

