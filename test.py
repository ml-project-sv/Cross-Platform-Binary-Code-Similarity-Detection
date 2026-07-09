import logging
for n in ['angr','cle','pyvex','claripy']: logging.getLogger(n).setLevel(logging.CRITICAL)
import angr, capstone
from capstone import x86, arm, mips

def imm_mem_reg_for(arch):
    a = arch.upper()
    if a.startswith('X86') or 'AMD64' in a: return x86.X86_OP_IMM, x86.X86_OP_MEM, x86.X86_OP_REG
    if a.startswith('ARM') or a.startswith('AARCH'): return arm.ARM_OP_IMM, arm.ARM_OP_MEM, arm.ARM_OP_REG
    if a.startswith('MIPS'): return mips.MIPS_OP_IMM, mips.MIPS_OP_MEM, mips.MIPS_OP_REG
    return None, None, None

# paste your normalize_insn here ...

IMM_THRESHOLD = 5000

def normalize_insn(proj, ci, IMM, MEM, REG):
    ix = ci.insn
    mnem = ix.mnemonic.split('.')[0]
    parts = [mnem]

    is_transfer = bool(set(ix.groups) & {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP, capstone.CS_GRP_BRANCH_RELATIVE})
    
    for op in ix.operands:

        if REG is not None and op.type == REG:
            parts.append(ci.insn.reg_name(op.reg))

        elif IMM is not None and op.type == IMM:
            if is_transfer or abs(op.imm) > IMM_THRESHOLD:
                parts.append('IMM')
            else:
                parts.append(str(op.imm))
        
        elif MEM is not None and op.type == MEM:
            m = op.mem
            base  = m.base  if hasattr(m, 'base')  else 0
            index = m.index if hasattr(m, 'index') else 0
            disp  = m.disp  if hasattr(m, 'disp')  else 0
            
            if base == 0 and index == 0:
                parts.append('MEM')
            else:
                b = ci.insn.reg_name(base)  if base != 0 else ''
                i = ci.insn.reg_name(index) if index != 0 else ''
                regs = '+'.join([r for r in (b, i) if r])
                if abs(disp) > IMM_THRESHOLD:
                    d = '+IMM'
                elif disp:
                    d = f'{disp:+d}'
                else:
                    d = ''

                parts.append(f'[{regs}{d}]')                

        else:
            parts.append('op')

    return ' '.join(parts)


def sample(so_path, n=40):
    proj = angr.Project(so_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    IMM, MEM, REG = imm_mem_reg_for(proj.arch.name)
    print(f"\n===== {so_path}  (arch={proj.arch.name}) =====")
    shown = 0
    for func in cfg.kb.functions.values():
        if not func.name or func.name.startswith('sub_'): continue
        for bn in sorted(func.graph.nodes(), key=lambda x:x.addr):
            blk = proj.factory.block(bn.addr, size=bn.size)
            for ci in blk.capstone.insns:
                raw = f"{ci.insn.mnemonic} {ci.insn.op_str}"
                tok = normalize_insn(proj, ci, IMM, MEM, REG)
                print(f"  {raw:38} -> {tok}")
                shown += 1
                if shown >= n: return
        if shown >= n: return

# run on one binary per arch:
sample("data_compiled/zlib_so/zlib-1.3.1-arm32-O0.so")
sample("data_compiled/zlib_so/zlib-1.3.1-mips32-O0.so")
sample("data_compiled/zlib_so/zlib-1.3.1-x86-O0.so")