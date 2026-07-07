import os, sys, json, logging
import angr, capstone
import networkx as nx
from capstone import x86, arm, mips
from collections import defaultdict

# make angr save metadata in /tmp
os.environ['TMPDIR'] = '/tmp'
os.environ['ANGR_CACHE_DIR'] = '/tmp/angr_cache'
os.makedirs('/tmp/angr_cache', exist_ok=True)

SKIP    = {'_init', '_fini', 'frame_dummy', 'register_tm_clones', 'deregister_tm_clones', '__do_global_ctors_aux', '__do_global_dtors_aux', 'atexit', '__libc_csu_init', '__libc_csu_fini', 'call_weak_fn', 'abort', '__gmon_start__'}
FEAT    = ['str', 'imm', 'branch', 'call', 'insns', 'arith', 'outdeg', 'betw', 'logic', 'shift', 'mul', 'div', 'move', 'cmp', 'pushpop', 'meminsn', 'fpsimd', 'indeg', 'operands', 'mnems', 'size']

ARITH   = {'add', 'sub', 'adc', 'sbb', 'inc', 'dec', 'neg', 'adds', 'subs', 'rsb', 'mla', 'mls', 'addu', 'addiu', 'subu', 'lea', 'abs', 'adr'}
LOGIC   = {'and', 'or', 'xor', 'not', 'test', 'orr', 'eor', 'bic', 'mvn', 'tst', 'andi', 'ori', 'xori', 'nor', 'ands', 'orrs'}
SHIFT   = {'shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'lsl', 'lsr', 'asr', 'sll', 'srl', 'sra', 'sllv', 'srlv', 'srav', 'rrx'}
MUL     = {'mul', 'imul', 'umull', 'smull', 'mult', 'multu', 'madd'}
DIV     = {'div', 'idiv', 'sdiv', 'udiv', 'divu'}
MOVE    = {'mov', 'movz', 'movk', 'movt', 'movw', 'ld', 'ldr', 'ldm', 'st', 'str', 'stm', 'lw', 'sw', 'li', 'la', 'lui', 'ldur', 'stur', 'ldp', 'stp', 'mflo', 'mfhi'}
CMP     = {'cmp', 'cmn', 'test', 'tst', 'slt', 'slti', 'sltu', 'fcmp', 'ucomiss'}
PUSHPOP = {'push', 'pop', 'pushad', 'popad'}
FPSIMD  = {'addsd', 'subsd', 'mulsd', 'divsd', 'movss', 'movsd', 'movaps', 'movups', 'paddd', 'pmuludq', 'pxor', 'vadd', 'vmul', 'vsub', 'fadd', 'fmul', 'fsub', 'fdiv', 'vldr', 'vstr', 'vmov', 'cvtsi2sd', 'cvttsd2si'}

# imm and mem constants for given arch
def imm_mem_for(arch):
    a = arch.upper()
    if a.startswith('X86')  or 'AMD64' in a: 
        return x86.X86_OP_IMM, x86.X86_OP_MEM
    
    if a.startswith('ARM')  or a.startswith('AARCH'): 
        return arm.ARM_OP_IMM, arm.ARM_OP_MEM
    
    if a.startswith('MIPS'): 
        return mips.MIPS_OP_IMM, mips.MIPS_OP_MEM
    return None, None


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


def block_features_for(proj, blk, out_deg, in_deg, betw, IMM, MEM):
    f = defaultdict(float)
    insns = blk.capstone.insns

    f['insns']  = len(insns)
    f['outdeg'] = out_deg
    f['betw']   = betw
    f['indeg']  = in_deg
    f['size']   = blk.size or 0

    mnems = set()
    for ci in insns:
        ix = ci.insn
        mnem = ix.mnemonic.split('.')[0]
        mnems.add(mnem)
        gr = set(ix.groups)

        if capstone.CS_GRP_CALL in gr: 
            f['call'] += 1
        
        if gr & {capstone.CS_GRP_JUMP, capstone.CS_GRP_RET, capstone.CS_GRP_BRANCH_RELATIVE, capstone.CS_GRP_CALL}:
            f['branch'] += 1

        if mnem in ARITH:   f['arith'] += 1
        if mnem in LOGIC:   f['logic'] += 1
        if mnem in SHIFT:   f['shift'] += 1
        if mnem in MUL:     f['mul'] += 1
        if mnem in DIV:     f['div'] += 1
        if mnem in MOVE:    f['move'] += 1
        if mnem in CMP:     f['cmp'] += 1
        if mnem in PUSHPOP: f['pushpop'] += 1
        if mnem in FPSIMD:  f['fpsimd'] += 1

        meminsn = False
        for op in ix.operands:
            f['operands'] += 1

            if IMM is not None and op.type == IMM:
                f['imm'] += 1

                if is_string_at(proj, op.imm):
                    f['str'] += 1
            
            if MEM is not None and op.type == MEM:
                meminsn = True
                disp = getattr(op.mem, 'disp', 0)
                if disp and is_string_at(proj, disp): 
                    f['str'] += 1

        if meminsn:
            f['meminsn'] += 1

    f['mnems'] = len(mnems)

    return [f[feat] for feat in FEAT]


def extract(so_path, src_tag, out_path):
    proj = angr.Project(so_path, auto_load_libs=False)
    cfg  = proj.analyses.CFGFast(normalize=True)
    
    n_funcs_written = 0
    IMM, MEM = imm_mem_for(proj.arch.name)

    with open(out_path, 'w') as out:

        for func in cfg.kb.functions.values():
            # check if function is valid
            if func.is_plt or func.is_simprocedure or not func.name: continue
            if func.name.startswith('sub_') or func.size <= 0: continue
            if func.name in SKIP or func.name.startswith(('__x86', '__gmon', '_GLOBAL', '__mips')): continue

            # extract nodes
            nodes = sorted(func.graph.nodes(), key=lambda n: n.addr)
            if not nodes: continue

            # extract graph and init adjacency array
            indices = {n.addr: i for i, n in enumerate(nodes)}
            G = nx.DiGraph(); G.add_nodes_from(range(len(nodes)))
            succs = [[] for _ in nodes]

            for u, v in func.graph.edges():
                if u.addr in indices and v.addr in indices:
                    ui, vi = indices[u.addr], indices[v.addr]
                    succs[ui].append(vi); G.add_edge(ui, vi)

            # calculate indegree and betweenness centrality of nodes
            betw  = nx.betweenness_centrality(G) if len(nodes) > 2 else {i: 0.0 for i in range(len(nodes))}
            indeg = dict(G.in_degree())

            # calculate features for nodes
            features = []
            for i, bn in enumerate(nodes):
                blk = proj.factory.block(bn.addr, size=bn.size)
                features.append(block_features_for(proj, blk, len(succs[i]), indeg.get(i, 0), betw.get(i, 0.0), IMM, MEM))

            out.write(json.dumps({'src': f'{src_tag}/{func.name}', 'fname': func.name, 'n_num': len(nodes), 'succs': succs, 'features': features}) + '\n')
            n_funcs_written += 1

    return n_funcs_written

if __name__ == '__main__':
    so_path, src_tag, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    n_funcs_written = extract(so_path, src_tag, out_path)
    print(f'{n_funcs_written} extracted from {so_path}')
