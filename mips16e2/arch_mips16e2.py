try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from archinfo.arch import Arch, register_arch, Endness, Register
from archinfo.tls import TLSArchInfo

class ArchMIPS16e2(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchMIPS16e2, self).__init__(endness)
        if endness == Endness.BE:
            self.qemu_name = 'mips'
            self.triplet = 'mips-linux-gnu'
            self.linux_name = 'mips'
        
    bits = 32
    vex_arch = "VexArchMIPS16e2"
    name = "MIPS16e2"
    ida_processor = 'mipsel'
    qemu_name = 'mipsel'
    linux_name = 'mipsel' # ???
    triplet = 'mipsel-linux-gnu'
    max_inst_bytes = 4
    ret_offset = 16
    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -4
    branch_delay_slot = True
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_MIPS
        cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    if _keystone:
        ks_arch = _keystone.KS_ARCH_MIPS
        ks_mode = _keystone.KS_MODE_32 + _keystone.KS_MODE_LITTLE_ENDIAN
    
    # Not sure if will be used.
    uc_arch = _unicorn.UC_ARCH_MIPS if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.mips_const if _unicorn else None
    uc_prefix = "UC_MIPS_" if _unicorn else None
    
    nop_instruction = b"\x65\x00"
    instruction_alignment = 2
    register_list = [
        Register(name='zero', size=4, alias_names=('r0',)),
        Register(name='at', size=4, alias_names=('r1',),
                 general_purpose=True),
        Register(name='v0', size=4, alias_names=('r2',),
                 general_purpose=True, linux_entry_value='ld_destructor'),
        Register(name='v1', size=4, alias_names=('r3',),
                 general_purpose=True),
        Register(name='a0', size=4, alias_names=('r4',),
                 general_purpose=True, argument=True),
        Register(name='a1', size=4, alias_names=('r5',),
                 general_purpose=True, argument=True),
        Register(name='a2', size=4, alias_names=('r6',),
                 general_purpose=True, argument=True),
        Register(name='a3', size=4, alias_names=('r7',),
                 general_purpose=True, argument=True),
        Register(name='t0', size=4, alias_names=('r8',),
                 general_purpose=True),
        Register(name='t1', size=4, alias_names=('r9',),
                 general_purpose=True),
        Register(name='t2', size=4, alias_names=('r10',),
                 general_purpose=True),
        Register(name='t3', size=4, alias_names=('r11',),
                 general_purpose=True),
        Register(name='t4', size=4, alias_names=('r12',),
                 general_purpose=True),
        Register(name='t5', size=4, alias_names=('r13',),
                 general_purpose=True),
        Register(name='t6', size=4, alias_names=('r14',),
                 general_purpose=True),
        Register(name='t7', size=4, alias_names=('r15',),
                 general_purpose=True),
        Register(name='s0', size=4, alias_names=('r16',),
                 general_purpose=True),
        Register(name='s1', size=4, alias_names=('r17',),
                 general_purpose=True),
        Register(name='s2', size=4, alias_names=('r18',),
                 general_purpose=True),
        Register(name='s3', size=4, alias_names=('r19',),
                 general_purpose=True),
        Register(name='s4', size=4, alias_names=('r20',),
                 general_purpose=True),
        Register(name='s5', size=4, alias_names=('r21',),
                 general_purpose=True),
        Register(name='s6', size=4, alias_names=('r22',),
                 general_purpose=True),
        Register(name='s7', size=4, alias_names=('r23',),
                 general_purpose=True),
        Register(name='t8', size=4, alias_names=('r24',),
                 general_purpose=True),
        Register(name='t9', size=4, alias_names=('r25',),
                 general_purpose=True, persistent=True),
        Register(name='k0', size=4, alias_names=('r26',),
                 general_purpose=True),
        Register(name='k1', size=4, alias_names=('r27',),
                 general_purpose=True),
        Register(name='gp', size=4, alias_names=('r28',),
                 persistent=True),
        Register(name='sp', size=4, alias_names=('r29',),
                 default_value=(Arch.initial_sp, True, 'global')),
        Register(name='s8', size=4, alias_names=('r30', 'fp', 'bp'),
                 general_purpose=True),
        Register(name='ra', size=4, alias_names=('r31', 'lr'),
                 general_purpose=True, persistent=True, linux_entry_value=0),
        Register(name='pc',  size=4, alias_names=('ip',)),
        Register(name='hi',  size=4, general_purpose=True),
        Register(name='lo',  size=4, general_purpose=True),
        Register(name='f0',  size=8, floating_point=True, subregisters=[('f0_lo', 0, 4)]),
        Register(name='f1',  size=8, floating_point=True, subregisters=[('f1_lo', 0, 4)]),
        Register(name='f2',  size=8, floating_point=True, subregisters=[('f2_lo', 0, 4)]),
        Register(name='f3',  size=8, floating_point=True, subregisters=[('f3_lo', 0, 4)]),
        Register(name='f4',  size=8, floating_point=True, subregisters=[('f4_lo', 0, 4)]),
        Register(name='f5',  size=8, floating_point=True, subregisters=[('f5_lo', 0, 4)]),
        Register(name='f6',  size=8, floating_point=True, subregisters=[('f6_lo', 0, 4)]),
        Register(name='f7',  size=8, floating_point=True, subregisters=[('f7_lo', 0, 4)]),
        Register(name='f8',  size=8, floating_point=True, subregisters=[('f8_lo', 0, 4)]),
        Register(name='f9',  size=8, floating_point=True, subregisters=[('f9_lo', 0, 4)]),
        Register(name='f10', size=8, floating_point=True, subregisters=[('f10_lo', 0, 4)]),
        Register(name='f11', size=8, floating_point=True, subregisters=[('f11_lo', 0, 4)]),
        Register(name='f12', size=8, floating_point=True, subregisters=[('f12_lo', 0, 4)]),
        Register(name='f13', size=8, floating_point=True, subregisters=[('f13_lo', 0, 4)]),
        Register(name='f14', size=8, floating_point=True, subregisters=[('f14_lo', 0, 4)]),
        Register(name='f15', size=8, floating_point=True, subregisters=[('f15_lo', 0, 4)]),
        Register(name='f16', size=8, floating_point=True, subregisters=[('f16_lo', 0, 4)]),
        Register(name='f17', size=8, floating_point=True, subregisters=[('f17_lo', 0, 4)]),
        Register(name='f18', size=8, floating_point=True, subregisters=[('f18_lo', 0, 4)]),
        Register(name='f19', size=8, floating_point=True, subregisters=[('f19_lo', 0, 4)]),
        Register(name='f20', size=8, floating_point=True, subregisters=[('f20_lo', 0, 4)]),
        Register(name='f21', size=8, floating_point=True, subregisters=[('f21_lo', 0, 4)]),
        Register(name='f22', size=8, floating_point=True, subregisters=[('f22_lo', 0, 4)]),
        Register(name='f23', size=8, floating_point=True, subregisters=[('f23_lo', 0, 4)]),
        Register(name='f24', size=8, floating_point=True, subregisters=[('f24_lo', 0, 4)]),
        Register(name='f25', size=8, floating_point=True, subregisters=[('f25_lo', 0, 4)]),
        Register(name='f26', size=8, floating_point=True, subregisters=[('f26_lo', 0, 4)]),
        Register(name='f27', size=8, floating_point=True, subregisters=[('f27_lo', 0, 4)]),
        Register(name='f28', size=8, floating_point=True, subregisters=[('f28_lo', 0, 4)]),
        Register(name='f29', size=8, floating_point=True, subregisters=[('f29_lo', 0, 4)]),
        Register(name='f30', size=8, floating_point=True, subregisters=[('f30_lo', 0, 4)]),
        Register(name='f31', size=8, floating_point=True, subregisters=[('f31_lo', 0, 4)]),
        Register(name='fir', size=4, floating_point=True),
        Register(name='fccr', size=4, floating_point=True),
        Register(name='fexr', size=4, floating_point=True),
        Register(name='fenr', size=4, floating_point=True),
        Register(name='fcsr', size=4, floating_point=True),
        Register(name='ulr', size=4),
        Register(name='emnote', size=4, artificial=True),
        Register(name='cmstart', size=4),
        Register(name='cmlen', size=4),
        Register(name='nraddr', size=4),
        Register(name='cond', size=4),
        Register(name='dspcontrol', size=4),
        Register(name='ac0', size=8),
        Register(name='ac1', size=8),
        Register(name='ac2', size=8),
        Register(name='ac3', size=8),
        Register(name='cp0_status', size=4),
        Register(name='ip_at_syscall', size=4, artificial=True),
    ]

    got_section_name = '.got'
    ld_linux_name = 'ld.so.1'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0x7000, 0x8000)