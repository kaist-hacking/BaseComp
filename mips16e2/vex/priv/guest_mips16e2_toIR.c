
/*--------------------------------------------------------------------*/
/*--- begin                                  guest_mips16e2_toIR.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2010-2015 RT-RK
      mips-valgrind@rt-rk.com

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

/* Translates MIPS16e2 code to IR. */

#include "libvex_basictypes.h"
#include "libvex_ir.h"
#include "libvex.h"
#include "libvex_guest_mips32.h"

#include "main_util.h"
#include "main_globals.h"
#include "guest_generic_bb_to_IR.h"
#include "guest_mips_defs.h"

/*------------------------------------------------------------*/
/*---                      Globals                         ---*/
/*------------------------------------------------------------*/

/* These are set at the start of the translation of a instruction, so
   that we don't have to pass them around endlessly. CONST means does
   not change during translation of the instruction. */

/* CONST: what is the host's endianness?  This has to do with float vs
   double register accesses on VFP, but it's complex and not properly
   thought out. */
static VexEndness host_endness;

/* Whether code we're analyzing comes from a big or little endian machine */
static IREndness guest_endness;

/* Pointer to the guest code area. */
static const UChar *guest_code;

/* CONST: The guest address for the instruction currently being
   translated. */
static Addr64 guest_PC_curr_instr;

/* MOD: The IRSB* into which we're generating code. */
static IRSB *irsb;

/* Is our guest binary 32 or 64bit? Set at each call to
   disInstr_MIPS below. */
static Bool mode64 = False;

#define OFFB_PC offsetof(VexGuestMIPS32State, guest_PC)

/* Define 1.0 in single and double precision. */
#define ONE_SINGLE 0x3F800000
#define ONE_DOUBLE 0x3FF0000000000000ULL

/* Define values to t8, gp, sp, ra. */
#define REG_T8 24
#define REG_GP 28
#define REG_SP 29
#define REG_RA 31
#define REG_PC 32

/*------------------------------------------------------------*/
/*---                  Debugging output                    ---*/
/*------------------------------------------------------------*/

#ifndef _MSC_VER
#define DIP(format, args...)           \
   if (vex_traceflags & VEX_TRACE_FE)  \
      vex_printf(format, ## args)

#else
#define DIP(format, ...)           \
   if (vex_traceflags & VEX_TRACE_FE)  \
      vex_printf(format, __VA_ARGS__)
#endif

/*------------------------------------------------------------*/
/*--- Helper bits and pieces for deconstructing the        ---*/
/*--- mips insn stream.                                    ---*/
/*------------------------------------------------------------*/

/* ---------------- Integer registers ---------------- */

static UInt xlat(UInt iregNo16e) {
   UInt ret;
   switch (iregNo16e) {
      case 0:
         ret = 16; break;
      case 1:
         ret = 17; break;
      case 2:
         ret = 2; break;
      case 3:
         ret = 3; break;
      case 4:
         ret = 4; break;
      case 5:
         ret = 5; break;
      case 6:
         ret = 6; break;
      case 7:
         ret = 7; break;
      default:
			vassert(0);
   }
   return ret;
}

static UInt integerGuestRegOffset(UInt iregNo)
{
   /* Do we care about endianness here?  We do if sub-parts of integer
      registers are accessed, but I don't think that ever happens on
      MIPS. */
   UInt ret;
   switch (iregNo) {
      case 0:
         ret = offsetof(VexGuestMIPS32State, guest_r0); break;
      case 1:
         ret = offsetof(VexGuestMIPS32State, guest_r1); break;
      case 2:
         ret = offsetof(VexGuestMIPS32State, guest_r2); break;
      case 3:
         ret = offsetof(VexGuestMIPS32State, guest_r3); break;
      case 4:
         ret = offsetof(VexGuestMIPS32State, guest_r4); break;
      case 5:
         ret = offsetof(VexGuestMIPS32State, guest_r5); break;
      case 6:
         ret = offsetof(VexGuestMIPS32State, guest_r6); break;
      case 7:
         ret = offsetof(VexGuestMIPS32State, guest_r7); break;
      case 8:
         ret = offsetof(VexGuestMIPS32State, guest_r8); break;
      case 9:
         ret = offsetof(VexGuestMIPS32State, guest_r9); break;
      case 10:
         ret = offsetof(VexGuestMIPS32State, guest_r10); break;
      case 11:
         ret = offsetof(VexGuestMIPS32State, guest_r11); break;
      case 12:
         ret = offsetof(VexGuestMIPS32State, guest_r12); break;
      case 13:
         ret = offsetof(VexGuestMIPS32State, guest_r13); break;
      case 14:
         ret = offsetof(VexGuestMIPS32State, guest_r14); break;
      case 15:
         ret = offsetof(VexGuestMIPS32State, guest_r15); break;
      case 16:
         ret = offsetof(VexGuestMIPS32State, guest_r16); break;
      case 17:
         ret = offsetof(VexGuestMIPS32State, guest_r17); break;
      case 18:
         ret = offsetof(VexGuestMIPS32State, guest_r18); break;
      case 19:
         ret = offsetof(VexGuestMIPS32State, guest_r19); break;
      case 20:
         ret = offsetof(VexGuestMIPS32State, guest_r20); break;
      case 21:
         ret = offsetof(VexGuestMIPS32State, guest_r21); break;
      case 22:
         ret = offsetof(VexGuestMIPS32State, guest_r22); break;
      case 23:
         ret = offsetof(VexGuestMIPS32State, guest_r23); break;
      case 24:
         ret = offsetof(VexGuestMIPS32State, guest_r24); break;
      case 25:
         ret = offsetof(VexGuestMIPS32State, guest_r25); break;
      case 26:
         ret = offsetof(VexGuestMIPS32State, guest_r26); break;
      case 27:
         ret = offsetof(VexGuestMIPS32State, guest_r27); break;
      case 28:
         ret = offsetof(VexGuestMIPS32State, guest_r28); break;
      case 29:
         ret = offsetof(VexGuestMIPS32State, guest_r29); break;
      case 30:
         ret = offsetof(VexGuestMIPS32State, guest_r30); break;
      case 31:
         ret = offsetof(VexGuestMIPS32State, guest_r31); break;
      default:
         vassert(0);
         break;
   }
   return ret;
}

/* ---------------- Floating point registers ---------------- */
// do we even need this ? add later if needed;

static UInt accumulatorGuestRegOffset(UInt acNo)
{
   vassert(!mode64);
   vassert(acNo <= 3);
   UInt ret;
   switch (acNo) {
      case 0:
         ret = offsetof(VexGuestMIPS32State, guest_ac0); break;
      case 1:
         ret = offsetof(VexGuestMIPS32State, guest_ac1); break;
      case 2:
         ret = offsetof(VexGuestMIPS32State, guest_ac2); break;
      case 3:
         ret = offsetof(VexGuestMIPS32State, guest_ac3); break;
      default:
         vassert(0);
    break;
   }
   return ret;
}

/* Do a endian load of a 32-bit word, regardless of the endianness of the
   underlying host. */
 
// 3.16 MIPS16e Instruction Stream Organization and Endianness
// The instruction halfword is placed within the 32-bit (or 64-bit) memory element according to system endianness.
// • On a 32-bit processor in big-endian mode, the firs instruction is read from bits 31..16 and the second instruction is read from bits 15..0
// • On a 32-bit processor in little-endian mode, the firs instruction is read from bits 15..0 and the second instruction is read from bits 31..16
// The above rule also applies to all extended instructions, since they consist of two 16-bit halfwords. Similarly, JAL and
// JALX instructions should be viewed as consisting of two 16-bit halfwords, which means this rule also applies to them.
// For a 16-bit-instruction sequence, instructions are placed in memory so that an LH instruction with the PC as an argument fetches the instruction independent of system endianness.

// so we should first read the front 2 bytes, and if is extended, read the back 2 bytes then..?

static inline UInt getUInt(const UChar * p)
{
   UInt w = 0;
   if (guest_endness == Iend_LE) {
       w = (w << 8) | p[1];
       w = (w << 8) | p[0];
       w = (w << 8) | p[3];
       w = (w << 8) | p[2];
   } else {
		// not sure if layout is right for BE
       w = (w << 8) | p[2];
       w = (w << 8) | p[3];
       w = (w << 8) | p[0];
       w = (w << 8) | p[1];
   }
   return w;
}

#define BITS2(_b1,_b0) \
   (((_b1) << 1) | (_b0))

#define BITS3(_b2,_b1,_b0)                      \
  (((_b2) << 2) | ((_b1) << 1) | (_b0))

#define BITS4(_b3,_b2,_b1,_b0) \
   (((_b3) << 3) | ((_b2) << 2) | ((_b1) << 1) | (_b0))

#define BITS5(_b4,_b3,_b2,_b1,_b0)  \
   (((_b4) << 4) | BITS4((_b3),(_b2),(_b1),(_b0)))

#define BITS6(_b5,_b4,_b3,_b2,_b1,_b0)  \
   ((BITS2((_b5),(_b4)) << 4) \
    | BITS4((_b3),(_b2),(_b1),(_b0)))

#define BITS8(_b7,_b6,_b5,_b4,_b3,_b2,_b1,_b0)  \
   ((BITS4((_b7),(_b6),(_b5),(_b4)) << 4) \
    | BITS4((_b3),(_b2),(_b1),(_b0)))

#define LOAD_STORE_PATTERN \
   t1 = newTemp(Ity_I32); \
      assign(t1, binop(Iop_Add32, getIReg(rs), \
                                    mkU32(extend_s_16to32(imm)))); \
   
#define LOADX_STORE_PATTERN \
   t1 = newTemp(Ity_I32); \
      assign(t1, binop(Iop_Add32, getIReg(regRs), getIReg(regRt))); \

#define LWX_SWX_PATTERN \
   t2 = newTemp(Ity_I32); \
   assign(t2, binop(Iop_And32, mkexpr(t1), mkU32(0xFFFFFFFC))); \
   t4 = newTemp(Ity_I32); \
   assign(t4, binop(Iop_And32, mkexpr(t1), mkU32(0x00000003)))

#define SXXV_PATTERN(op) \
   putIReg(rd, binop(op, \
         getIReg(rt), \
            unop(Iop_32to8, \
               binop(Iop_And32, \
                  getIReg(rs), \
                  mkU32(0x0000001F) \
               ) \
            ) \
         ) \
      )

#define SXX_PATTERN(op) \
   putIReg(rd, binop(op, getIReg(rt), mkU8(sa)));

#define ALU_PATTERN(op) \
   putIReg(rd, binop(op, getIReg(rs), getIReg(rt)));

#define ALUI_PATTERN(op) \
   putIReg(rt, binop(op, getIReg(rs), mkU32(imm)));

#define ILLEGAL_INSTRUCTON \
   putPC(mkU32(guest_PC_curr_instr + 4)); \
   dres.jk_StopHere = Ijk_SigILL; \
   dres.whatNext    = Dis_StopHere;

/*------------------------------------------------------------*/
/*---                  Field helpers                       ---*/
/*------------------------------------------------------------*/

static UInt is_extended(UInt mipsins)
{
	// Returns 1 if extended.
	if ((mipsins >> 27) == 0b11110)
		return 1;
	return 0;
}

static UInt is_jal_or_jalx(UInt mipsins){
   // Returns 1 if JAL/JALX type.
   if ((mipsins >> 27) == 0b00011)
      return 1;
   return 0;
}

static UInt get_opcode(UInt mipsins)
{
   return (0x0000F800 & mipsins) >> 11;
}

static UInt get_rx(UInt mipsins)
{
	return (0x00000700 & mipsins) >> 8;
}

static UInt get_ry(UInt mipsins)
{
	return (0x000000E0 & mipsins) >> 5; 
}

static UInt get_i8_funct(UInt mipsins)
{
	return (0x00000700 & mipsins) >> 8;
}

static UInt get_imm_addiu(UInt mipsins){
	UInt imm = 0;
	imm = imm | (mipsins & 0x001F0000) >> 16;
	imm = (imm << 6) | (mipsins & 0x07E00000) >> 21;
	imm = (imm << 5) | (mipsins & 0x0000001F) >> 0;
	return imm;
}

static UInt get_imm_rri_addiu(UInt mipsins){
   UInt imm = 0;
   imm = imm | (mipsins & 0x000F0000) >> 16;
   imm = (imm << 7) | (mipsins & 0x07F00000) >> 20;
   imm = (imm << 4) | (mipsins & 0x0000000F) >> 0;
   return imm;
}

static UInt get_target_jal(UInt mipsins){
   UInt imm = 0;
   imm = imm | (mipsins & 0x001F0000) >> 16;
   imm = (imm << 5) | (mipsins & 0x03E00000) >> 21;
   imm = (imm << 16) | (mipsins & 0x0000FFFF) >> 0;
   return imm;
}

static UInt get_sel_addiu(UInt mipsins){
	return (0x000000E0 & mipsins) >> 5;
}

static UInt get_extended_sa(UInt mipsins){
   UInt imm = 0;
   imm = imm | (mipsins & 0x00100000) >> 21;
   imm = (imm << 5) | (mipsins & 0x07C00000) >> 22;
   return imm;
}

static Bool branch_or_jump(const UChar * addr)
{
   UInt cins = getUInt(addr);

   if (is_jal_or_jalx(cins)){ /* JAL, JALX */
      return True;
   }

   UInt extended = is_extended(cins);

	if (!extended){
		cins = cins >> 16;
	}

   UInt opcode = get_opcode(cins);
   UInt ry = get_ry(cins);

   if (opcode == 0b00010){ /* B */
      return True;
   }

   if (opcode == 0b00100){ /* BEQZ */
      return True;
   }
   
   if (opcode == 0b00101){ /* BNEZ */
      return True;
   }

   if (opcode == 0b01100){
      UInt i8_funct = get_i8_funct(cins);
      if (i8_funct == 0b000){ /* BTEQZ */
         return True;
      }
      if (i8_funct == 0b001){ /* BTNEZ */
         return True;
      }
   }

   if (opcode == 0b11101) {
      UInt rr_funct = (cins & 0x1F) >> 0;
      if (rr_funct == 0b00000) {
         switch (ry) {
            case 0b000:
            case 0b001:
            case 0b010:
            case 0b100:
            case 0b101:
            case 0b110:
               return True;
            case 0b011:
            case 0b111:
            default:
               break;
         }
      }
   }

	return False;
}

static Bool is_Branch_or_Jump_and_Link(const UChar * addr)
{
   UInt cins = getUInt(addr);

   if (is_jal_or_jalx(cins)){ /* JAL, JALX */
      return True;
   }

   UInt extended = is_extended(cins);

	if (!extended){
		cins = cins >> 16;
	}

   UInt opcode = get_opcode(cins);
   UInt ry = get_ry(cins);
   UInt rr_funct = (cins & 0x1F) >> 0;

   if (opcode == 0b11101) { /* RR */
      if (rr_funct == 0b00000) {
         if (ry == 0b010) /* JALR */
            return True;
         if (ry == 0b110) /* JALRC */
            return True;
      }
   }

	return False;
}

static Bool is_Ret(const UChar * addr)
{
   UInt cins = getUInt(addr);

   if (is_jal_or_jalx(cins)){
      return False;
   }

   UInt extended = is_extended(cins);
   
   if (!extended){
      cins = cins >> 16;
	}

   UInt opcode = get_opcode(cins);
   UInt ry = get_ry(cins);
   UInt rr_funct = (cins & 0x1F) >> 0;

   if (opcode == 0b11101) { /* RR */
      if (rr_funct == 0b00000) {
         if (ry == 0b001) /* JR ra */
            return True;
         if (ry == 0b101) /* JRC ra */
            return True;
      }
   }

	return False;
}

/*------------------------------------------------------------*/
/*--- Helper bits and pieces for creating IR fragments.    ---*/
/*------------------------------------------------------------*/

static IRExpr *mkU8(UInt i)
{
   vassert(i < 256);
   return IRExpr_Const(IRConst_U8((UChar) i));
}

/* Create an expression node for a 16-bit integer constant. */
static IRExpr *mkU16(UInt i)
{
   return IRExpr_Const(IRConst_U16(i));
}

/* Create an expression node for a 32-bit integer constant. */
static IRExpr *mkU32(UInt i)
{
   return IRExpr_Const(IRConst_U32(i));
}

static IRExpr *mkexpr(IRTemp tmp)
{
   return IRExpr_RdTmp(tmp);
}

static IRExpr *unop(IROp op, IRExpr * a)
{
   return IRExpr_Unop(op, a);
}

static IRExpr *binop(IROp op, IRExpr * a1, IRExpr * a2)
{
   return IRExpr_Binop(op, a1, a2);
}

static IRExpr *triop(IROp op, IRExpr * a1, IRExpr * a2, IRExpr * a3)
{
   return IRExpr_Triop(op, a1, a2, a3);
}

static IRExpr *qop ( IROp op, IRExpr * a1, IRExpr * a2, IRExpr * a3,
                     IRExpr * a4 )
{
   return IRExpr_Qop(op, a1, a2, a3, a4);
}

static IRExpr *load(IRType ty, IRExpr * addr)
{
   return IRExpr_Load(guest_endness, ty, addr);
}

/* Add a statement to the list held by "irsb". */
static void stmt(IRStmt * st)
{
   addStmtToIRSB(irsb, st);
}

static void assign(IRTemp dst, IRExpr * e)
{
   stmt(IRStmt_WrTmp(dst, e));
}

static void store(IRExpr * addr, IRExpr * data)
{
   stmt(IRStmt_Store(guest_endness, addr, data));
}

/* Generate a new temporary of the given type. */
static IRTemp newTemp(IRType ty)
{
   vassert(isPlausibleIRType(ty));
   return newIRTemp(irsb->tyenv, ty);
}

/* Generate an expression for SRC rotated right by ROT. */
static IRExpr *genROR32(IRExpr * src, Int rot)
{
   vassert(rot >= 0 && rot < 32);
   if (rot == 0)
      return src;
   return binop(Iop_Or32, binop(Iop_Shl32, src, mkU8(32 - rot)),
                          binop(Iop_Shr32, src, mkU8(rot)));
}

static IRExpr *genRORV32(IRExpr * src, IRExpr * rs)
{
   IRTemp t0 = newTemp(Ity_I8);
   IRTemp t1 = newTemp(Ity_I8);

   assign(t0, unop(Iop_32to8, binop(Iop_And32, rs, mkU32(0x0000001F))));
   assign(t1, binop(Iop_Sub8, mkU8(32), mkexpr(t0)));
   return binop(Iop_Or32, binop(Iop_Shl32, src, mkexpr(t1)),
                          binop(Iop_Shr32, src, mkexpr(t0)));
}

static UShort extend_s_10to16(UInt x)
{
   return (UShort) ((((Int) x) << 22) >> 22);
}

static UInt extend_s_4to32(UInt x)
{
   return (UInt) ((((Int) x) << 28) >> 28);
}

static UInt extend_s_8to32(UInt x)
{
   return (UInt) ((((Int) x) << 24) >> 24);
}

static UInt extend_s_9to32(UInt x)
{
   return (UInt) ((((Int) x) << 23) >> 23);
}

static UInt extend_s_10to32(UInt x)
{
   return (UInt) ((((Int) x) << 22) >> 22);
}

static UInt extend_s_11to32(UInt x)
{
   return (UInt) ((((Int) x) << 21) >> 21);
}

static UInt extend_s_12to32(UInt x)
{
   return (UInt) ((((Int) x) << 20) >> 20);
}

static UInt extend_s_15to32(UInt x)
{
   return (UInt) ((((Int) x) << 17) >> 17);
}

static UInt extend_s_16to32(UInt x)
{
   return (UInt) ((((Int) x) << 16) >> 16);
}

static UInt extend_s_17to32(UInt x)
{
   return (UInt) ((((Int) x) << 15) >> 15);
}

static UInt extend_s_18to32(UInt x)
{
   return (UInt) ((((Int) x) << 14) >> 14);
}

static void jmp_lit32 ( /*MOD*/ DisResult* dres, IRJumpKind kind, Addr32 d32 )
{
   vassert(dres->len         == 0);
   vassert(dres->continueAt  == 0);
   vassert(dres->jk_StopHere == Ijk_INVALID);
   dres->whatNext    = Dis_StopHere;
   dres->jk_StopHere = kind;
   stmt( IRStmt_Put( OFFB_PC, mkU32(d32) ) );
}

/* Get value from accumulator (helper function for MIPS32 DSP ASE instructions).
   This function should be called before any other operation if widening
   multiplications are used. */
static IRExpr *getAcc(UInt acNo)
{
   vassert(!mode64);
   vassert(acNo <= 3);
   return IRExpr_Get(accumulatorGuestRegOffset(acNo), Ity_I64);
}

/* Fetch a byte from the guest insn stream. */
static UChar getIByte(Int delta)
{
   return guest_code[delta];
}

static IRExpr *getIReg(UInt iregNo)
{
   if (0 == iregNo) {
      return mkU32(0x0);
   } else {
      IRType ty = Ity_I32;
      vassert(iregNo < 32);
      return IRExpr_Get(integerGuestRegOffset(iregNo), ty);
   }
}

static IRExpr *getHI(void)
{
   return IRExpr_Get(offsetof(VexGuestMIPS32State, guest_HI), Ity_I32);
}

static IRExpr *getLO(void)
{
   return IRExpr_Get(offsetof(VexGuestMIPS32State, guest_LO), Ity_I32);
}

/* Get byte from register reg, byte pos from 0 to 3 (or 7 for MIPS64) . */
static IRExpr *getByteFromReg(UInt reg, UInt byte_pos)
{
   UInt pos = byte_pos * 8;
   return unop(Iop_32to8, binop(Iop_And32,
                                 binop(Iop_Shr32, getIReg(reg), mkU8(pos)),
                                 mkU32(0xFF)));
}

static void putIReg(UInt archreg, IRExpr * e)
{
   IRType ty = Ity_I32;
   vassert(archreg < 32);
   vassert(typeOfIRExpr(irsb->tyenv, e) == ty);
   if (archreg != 0)
      stmt(IRStmt_Put(integerGuestRegOffset(archreg), e));
}

static void putLO(IRExpr * e)
{
   stmt(IRStmt_Put(offsetof(VexGuestMIPS32State, guest_LO), e));
   /* Add value to lower 32 bits of ac0 to maintain compatibility between
      regular MIPS32 instruction set and MIPS DSP ASE. Keep higher 32bits
      unchanged. */
   IRTemp t_lo = newTemp(Ity_I32);
   IRTemp t_hi = newTemp(Ity_I32);
   assign(t_lo, e);
   assign(t_hi, unop(Iop_64HIto32, getAcc(0)));
   stmt(IRStmt_Put(accumulatorGuestRegOffset(0),
         binop(Iop_32HLto64, mkexpr(t_hi), mkexpr(t_lo))));
}

static void putHI(IRExpr * e)
{
   stmt(IRStmt_Put(offsetof(VexGuestMIPS32State, guest_HI), e));
   /* Add value to higher 32 bits of ac0 to maintain compatibility between
      regular MIPS32 instruction set and MIPS DSP ASE. Keep lower 32bits
      unchanged. */
   IRTemp t_lo = newTemp(Ity_I32);
   IRTemp t_hi = newTemp(Ity_I32);
   assign(t_hi, e);
   assign(t_lo, unop(Iop_64to32, getAcc(0)));
   stmt(IRStmt_Put(accumulatorGuestRegOffset(0),
         binop(Iop_32HLto64, mkexpr(t_hi), mkexpr(t_lo))));
}

static void putPC(IRExpr * e)
{
   stmt(IRStmt_Put(OFFB_PC, e));
}

/* Narrow 8/16/32 bit int expr to 8/16/32.  Clearly only some
   of these combinations make sense. */
static IRExpr *narrowTo(IRType dst_ty, IRExpr * e)
{
   IRType src_ty = typeOfIRExpr(irsb->tyenv, e);
   if (src_ty == dst_ty)
      return e;
   if (src_ty == Ity_I32 && dst_ty == Ity_I16)
      return unop(Iop_32to16, e);
   if (src_ty == Ity_I32 && dst_ty == Ity_I8)
      return unop(Iop_32to8, e);
   if (src_ty == Ity_I64 && dst_ty == Ity_I8) {
      vassert(mode64);
      return unop(Iop_64to8, e);
   }
   if (src_ty == Ity_I64 && dst_ty == Ity_I16) {
      vassert(mode64);
      return unop(Iop_64to16, e);
   }
   vpanic("narrowTo(mips)");
   return 0;
}

static void dis_branch( Bool link, IRExpr * guard, UInt imm, IRStmt ** set,
                        UInt len )
{
   ULong branch_offset;
   IRTemp t0;

   // May need to handle this.
   if (link) {  /* LR (GPR31) = addr of the 2nd instr after branch instr */
		putIReg(31, mkU32(guest_PC_curr_instr + 8));
   }

   /* The imm must be handled prior calling this function. */
	branch_offset = imm;

   t0 = newTemp(Ity_I1);
   assign(t0, guard);
	*set = IRStmt_Exit(mkexpr(t0), link ? Ijk_Call : Ijk_Boring,
								IRConst_U32(guest_PC_curr_instr + len +
												(UInt) branch_offset), OFFB_PC);
}

/*------------------------------------------------------------*/
/*---          Disassemble a single instruction            ---*/
/*------------------------------------------------------------*/

/* Disassemble a single instruction into IR. The instruction is
   located in host memory at guest_instr, and has guest IP of
   guest_PC_curr_instr, which will have been set before the call
   here. */

static DisResult disInstr_MIPS16e2_WRK ( Bool(*resteerOkFn) (/*opaque */void *,
                                                                    Addr),
                                     Bool         resteerCisOk,
                                     void*        callback_opaque,
                                     Long         delta64,
                                     const VexArchInfo* archinfo,
                                     const VexAbiInfo*  abiinfo,
                                     Bool         sigill_diag )
{
   IRTemp   t0, t1 = 0, t2, t3, t4, t5, t6, t7, t8, t9,
            t10, t11, t12, t13, t14, t15, t16, t17;

   //UInt opcode, cins, rs, rt, rd, sa, ft, fs, fd, fmt, tf, nd, function,
   //     trap_code, imm, instr_index, p, msb, lsb, size, rot, sel;
	UInt rs, rt, rd;

	UInt  cins, op, imm, rx, ry, rz, sa, sel, jal_x, target, 
         shift_f, rri_a_f, i8_funct, svrs_s, r32, rrr_f, rr_funct,
         svrs_ra, svrs_s0, svrs_s1, svrs_framesize, svrs_aregs, svrs_xsregs,
         svrs_args, svrs_astatic, stack_cnt, mfc0_sel;
	UInt extended;
   UInt cins_t;
   UInt ISA_Mode;

   DisResult dres;

   static IRExpr *lastn = NULL;  /* last jump addr */
   static IRStmt *bstmt = NULL;  /* branch (Exit) stmt */

   /* The running delta */
   Int delta = (Int) delta64;

   /* Holds eip at the start of the insn, so that we can print
      consistent error messages for unimplemented insns. */
   Int delta_start = delta;

   /* Length of instructions. */
   Int dres_len = 0;
   Int prev_dres_len = 0;

   /* Are we in a delay slot ? */
   Bool delay_slot_branch, delay_slot_jump;

   /* Is this compact instruction? */
   Bool compact;

   /* For MUL & DIV. */
   IRExpr *e = NULL;

   /* Set result defaults. */
   dres.whatNext = Dis_Continue;
   dres.len = 0;
   dres.continueAt = 0;
   dres.jk_StopHere = Ijk_INVALID;
   dres.hint        = Dis_HintNone;

   delay_slot_branch = delay_slot_jump = False;
   compact = False;

   const UChar *code = guest_code + delta;
   cins = getUInt(code);
   DIP("\t0x%llx:\t0x%08x\t", (Addr64)guest_PC_curr_instr, cins);

   /* Can't decode a single instruction if it is a branch or jump
      (as the delay slot is also needed for meaningful decoding) */
   if ((vex_control.guest_max_insns == 1 || vex_control.guest_max_bytes < 8)
       && branch_or_jump(guest_code)) {
      goto decode_failure;
   }

   if (delta == 0) {
      lastn = NULL;
      bstmt = NULL;
   } else {
      if (delta == 2) {
         prev_dres_len = 2;
      } else {
         cins_t = getUInt(guest_code + delta - 4);
         if (is_extended(cins_t)) {
            prev_dres_len = 4;
         } else if (is_jal_or_jalx(cins_t)) {
            prev_dres_len = 4;
         } else {
            prev_dres_len = 2;
         }
      }
      if (branch_or_jump(guest_code + delta - prev_dres_len)) {
         if (lastn == NULL && bstmt == NULL) {
            vassert(0);
         } else {
            dres.whatNext = Dis_StopHere;
            if (lastn != NULL) {
               delay_slot_jump = True;
            } else if (bstmt != NULL) {
               delay_slot_branch = True;
            }
         }
      }
   }

	extended = is_extended(cins);

	if (!extended && !is_jal_or_jalx(cins)) {
      cins  = cins >> 16;
      dres_len = 2;
	} else {
      dres_len = 4;
   }

	op = get_opcode(cins);
	rx = get_rx(cins);
	ry = get_ry(cins);

   if (is_jal_or_jalx(cins)){
      op = 0b00011;
      rx = 0;
      ry = 0;
   }

   DIP("extended : %d\n", extended);
   DIP("op : %d\n", op);
   DIP("rx : %d\n", rx);
   DIP("ry : %d\n", ry);

   switch (op) {

		case 0b00000: /* ADDIUSP */
			/* ADDIU, relative to SP */
			if (extended) {
				sel = get_sel_addiu(cins);
				imm = get_imm_addiu(cins);
				if (sel == 0b000) {
					putIReg(xlat(rx), binop(Iop_Add32, getIReg(REG_SP),mkU32(extend_s_16to32(imm))));
				} else if (sel == 0b001) {
					putIReg(xlat(rx), binop(Iop_Add32, getIReg(REG_GP),mkU32(extend_s_16to32(imm))));
				} else {
					goto decode_failure;
				}
			} else {
				imm = (0xFF & cins) >> 0;
				putIReg(xlat(rx), binop(Iop_Add32, getIReg(REG_SP),mkU32(extend_s_10to32(imm<<2))));
			}
			break;

		case 0b00001: /* ADDIUPC */
			/* ADDIU, relative to PC */
			/* TODO: Check if delay slot is already considered. */
			/* Firmware doesn't use this instruction. */
			if (extended) {
				sel = get_sel_addiu(cins);
				imm = get_imm_addiu(cins);
				if (sel == 0b000) {
					putIReg(xlat(rx), binop(Iop_Add32, getIReg(REG_PC),mkU32(extend_s_16to32(imm))));
				} else {
					goto decode_failure;
				}
			} else {
				imm = (0xFF & cins) >> 0;
				putIReg(xlat(rx), binop(Iop_Add32, getIReg(REG_PC),mkU32(extend_s_10to32(imm<<2))));
			}
			break;

		case 0b00010: /* B */
			if (extended) {
				imm = extend_s_17to32(get_imm_addiu(cins) << 1);
            dis_branch(False, binop(Iop_CmpEQ32, getIReg(0), getIReg(0)), imm, &bstmt, dres_len);
			} else {
				imm = extend_s_12to32(((0x07FF & cins) >> 0) << 1);
				dis_branch(False, binop(Iop_CmpEQ32, getIReg(0), getIReg(0)), imm, &bstmt, dres_len);
			}
         break;

		case 0b00011: /* JAL(X) */
         /* Always 4 byte instructions. */
         jal_x = (0x04000000 & cins) >> 26;
         target = get_target_jal(cins);
         if (jal_x == 0) { /* JAL */
            putIReg(31, mkU32(guest_PC_curr_instr + 6));
            t0 = newTemp(Ity_I32);
            assign(t0, mkU32( (guest_PC_curr_instr & 0xF0000000) | 
                              (target << 2)));
            lastn = mkexpr(t0);
         } else { /* JALX */
            /* May need to handle ISA Mode. 
               Not implemented for now as all the targets are going to be hooked. */
            putIReg(31, mkU32(guest_PC_curr_instr + 6));
            t0 = newTemp(Ity_I32);
            assign(t0, mkU32( (guest_PC_curr_instr & 0xF0000000) | 
                              (target << 2)));
            lastn = mkexpr(t0);
         }
         break;

		case 0b00100: /* BEQZ */
         if (extended) {
				imm = extend_s_17to32(get_imm_addiu(cins) << 1);
            dis_branch(False, binop(Iop_CmpEQ32, getIReg(xlat(rx)), getIReg(0)), imm, &bstmt, dres_len);
			} else {
				imm = extend_s_9to32(((0xFF & cins) >> 0) << 1);
				dis_branch(False, binop(Iop_CmpEQ32, getIReg(xlat(rx)), getIReg(0)), imm, &bstmt, dres_len);
			}
         break;

		case 0b00101: /* BNEZ */
         if (extended) {
				imm = extend_s_17to32(get_imm_addiu(cins) << 1);
            dis_branch(False, binop(Iop_CmpNE32, getIReg(xlat(rx)), getIReg(0)), imm, &bstmt, dres_len);
			} else {
				imm = extend_s_9to32(((0xFF & cins) >> 0) << 1);
				dis_branch(False, binop(Iop_CmpNE32, getIReg(xlat(rx)), getIReg(0)), imm, &bstmt, dres_len);
			}
         break;

		case 0b00110: /* SHIFT */
         shift_f = (cins & 0x00000003) >> 0;
         if (extended) {
            sa = get_extended_sa(cins);
         } else {
            sa = (cins & 0x0000001C) >> 2;
            if (sa == 0) {
               sa = 8;
            }
         }
         rd = xlat(rx);
         rt = xlat(ry);

         switch (shift_f) {
            case 0b00: /* SLL */ /* 16e2 EHB EXT INS PAUSE RDHWR SYNC */
               if (extended) {
                  sel = (cins & 0x1C) >> 2;
                  switch (sel) {
                     case 0b000: /* SLL */
                        SXX_PATTERN(Iop_Shl32);
                        break;
                     
                     case 0b001: /* INS */
                        
                        //break;
                     
                     case 0b010: /* EXT */
                        
                        //break;
                     
                     case 0b011: /* RDHWR */
                        
                        //break;
                     
                     case 0b100: /* EHB */
                        
                        //break;
                     
                     case 0b101: /* SYNC */
                        
                        //break;
                     
                     case 0b110: /* PAUSE */
                        
                        //break;
                     
                     case 0b111:
                     default:
                        goto decode_failure;
                  }
               } else {
                  SXX_PATTERN(Iop_Shl32);
               }
               break;
            case 0b01:
               goto decode_failure;
            case 0b10: /* SRL */ /* 16e2 MOVZ MOVN MOVTN MOVTZ */
               if (extended) {
                  sel = (cins & 0x1C) >> 2;
                  switch (sel) {
                     case 0b000: /* SRL */
                        SXX_PATTERN(Iop_Shl32);
                        break;
                     
                     case 0b001: /* MOVZ */
                        
                        //break;
                     
                     case 0b010: /* MOVN */
                        
                        //break;
                     
                     case 0b011:
                     case 0b100:
                        goto decode_failure;
                     
                     case 0b101: /* MOVTZ */
                        
                        //break;
                     
                     case 0b110: /* MOVTN */
                        
                        //break;
                     
                     case 0b111:
                     default:
                        goto decode_failure;
                  }
               } else {
                  SXX_PATTERN(Iop_Shr32);
               }
               break;
            case 0b11: /* SRA */
               SXX_PATTERN(Iop_Sar32);
               break; 
            default:
               goto decode_failure;
         }
         break;

		case 0b00111: /* Reserved */
         goto decode_failure;

		case 0b01000: /* RRI-A */
         rri_a_f = (cins & 0x00000010) >> 4;
         if (rri_a_f == 0) { /* ADDIU */
            if (extended) {
               imm = extend_s_15to32(
                        get_imm_rri_addiu(cins)
                        );
            } else {
               imm = extend_s_8to32(
                        (0xFF & cins) >> 0
                        );
            }
            putIReg(xlat(ry), binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         } else { /* This field should be 0. */
            goto decode_failure;
         }
         break;

		case 0b01001: /* ADDIU8 */
         if (extended) {
            imm = extend_s_16to32(
                     get_imm_addiu(cins)
                     );
         } else {
            imm = extend_s_8to32(
                     (cins & 0xFF) >> 0
                     );
         }
         putIReg(xlat(rx), binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         break;

		case 0b01010: /* SLTI */
         if (extended) {
            imm = extend_s_16to32(
                     get_imm_addiu(cins)
                     );
         } else {
            imm = extend_s_8to32(
                     (cins & 0xFF) >> 0
                     );
         }
         putIReg(REG_T8, unop(Iop_1Uto32, binop(Iop_CmpLT32S, getIReg(xlat(rx)), mkU32(imm))));
         break;

		case 0b01011: /* SLTIU */
         if (extended) {
            imm = get_imm_addiu(cins);
         } else {
            imm = (cins & 0xFF) >> 0;
         }
         putIReg(REG_T8, unop(Iop_1Uto32, binop(Iop_CmpLT32U, getIReg(xlat(rx)), mkU32(imm))));
         break;

		case 0b01100: /* I8 */
         i8_funct = get_i8_funct(cins);
         switch (i8_funct) {
            case 0b000: /* BTEQZ */
               if (extended) {
                  imm = extend_s_17to32(
                           get_imm_addiu(cins) << 1
                           );
               } else {
                  imm = extend_s_9to32(
                           ((cins & 0xFF) >> 0) << 1
                           );
               }
               dis_branch(False, binop(Iop_CmpEQ32, getIReg(REG_T8), getIReg(0)), imm, &bstmt, dres_len);
               break;

            case 0b001: /* BTNEZ */
               if (extended) {
                  imm = extend_s_17to32(
                           get_imm_addiu(cins) << 1
                           );
               } else {
                  imm = extend_s_9to32(
                           ((cins & 0xFF) >> 0) << 1
                           );
               }
               dis_branch(False, binop(Iop_CmpNE32, getIReg(REG_T8), getIReg(0)), imm, &bstmt, dres_len);
               break;

            case 0b010: /* SWRASP */
               /* SW ra, offset(sp) */
               if (extended) {
                  imm = get_imm_addiu(cins) << 2;
               } else {
                  imm = ((cins & 0xFF) >> 0) << 2;
               }
               t1 = newTemp(Ity_I32);
               assign(t1, binop(Iop_Add32, getIReg(REG_SP), mkU32(imm)));
               store(mkexpr(t1), getIReg(REG_RA));
               break;

            case 0b011: /* ADJSP */
               if (extended) {
                  imm = extend_s_16to32(
                           get_imm_addiu(cins)
                           );
               } else {
                  imm = extend_s_11to32(
                           ((cins & 0xFF) >> 0) << 3
                           );
               }
               putIReg(REG_SP, binop(Iop_Add32, getIReg(REG_SP),mkU32(imm)));
               break;

            case 0b100: /* SVRS */
               svrs_s  = (cins & 0x80) >> 7;
               svrs_ra = (cins & 0x40) >> 6;
               svrs_s0 = (cins & 0x20) >> 5;
               svrs_s1 = (cins & 0x10) >> 4;
               if (extended) {
                  svrs_framesize = 0;
                  svrs_framesize = svrs_framesize | (cins & 0x00F00000) >> 20;
                  svrs_framesize = (svrs_framesize << 4) | ((cins & 0xF) >> 0);
                  
                  svrs_aregs = (cins & 0x000F0000) >> 16;
                  svrs_xsregs = (cins & 0x07000000) >> 24;

                  switch (svrs_aregs) {
                     case 0b0000:
                     case 0b0001:
                     case 0b0010:
                     case 0b0011:
                     case 0b1011:
                        svrs_args = 0;                        
                        break;
                     case 0b0100:
                     case 0b0101:
                     case 0b0110:
                     case 0b0111:
                        svrs_args = 1;
                        break;
                     case 0b1000:
                     case 0b1001:
                     case 0b1010:
                        svrs_args = 2;
                        break;
                     case 0b1100:
                     case 0b1101:
                        svrs_args = 3;
                        break;
                     case 0b1110:
                        svrs_args = 4;
                        break;
                     default:
                        DIP("svrs_args failure : %d\n", svrs_aregs);
                        goto decode_failure;
                  }

                  switch (svrs_aregs) {
                     case 0b0000:
                     case 0b0100:
                     case 0b1000:
                     case 0b1100:
                     case 0b1110:
                        svrs_astatic = 0;                        
                        break;
                     case 0b0001:
                     case 0b0101:
                     case 0b1001:
                     case 0b1101:
                        svrs_astatic = 1;
                        break;
                     case 0b0010:
                     case 0b0110:
                     case 0b1010:
                        svrs_astatic = 2;
                        break;
                     case 0b0011:
                     case 0b0111:
                        svrs_astatic = 3;
                        break;
                     case 0b1011:
                        svrs_astatic = 4;
                        break;
                     default:
                       DIP("svrs_astatic failure : %d\n", svrs_aregs);
                        goto decode_failure;
                  }
               } else {
                  svrs_framesize = (cins & 0xF) >> 0;
               }
               switch (svrs_s) {
                  case 0: /* RESTORE */
                     stack_cnt = 0;
                     // Adjust stack with framesize.
                     t0 = newTemp(Ity_I32);
                     if (extended) {
                        assign(t0, binop(Iop_Add32, getIReg(29), mkU32(svrs_framesize << 3)));
                     } else {
                        if (svrs_framesize == 0) {
                           assign(t0, binop(Iop_Add32, getIReg(29), mkU32(128)));
                        } else {
                           assign(t0, binop(Iop_Add32, getIReg(29), mkU32(svrs_framesize << 3)));
                        }
                     }
                     putIReg(29, mkexpr(t0));
                     // Restore ra
                     if (svrs_ra) {
                        // Restore GPR[31]
                        stack_cnt += 1;
                        t1 = newTemp(Ity_I32);
                        assign(t1, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        putIReg(31, load(Ity_I32, mkexpr(t1)));
                     }
                     // Restore registers GPR[18-23,30]
                     if (extended) {
                        if (svrs_xsregs > 0) {
                           if (svrs_xsregs > 1) {
                              if (svrs_xsregs > 2) {
                                 if (svrs_xsregs > 3) {
                                    if (svrs_xsregs > 4) {
                                       if (svrs_xsregs > 5) {
                                          if (svrs_xsregs > 6) {
                                             // Restore GPR[30]
                                             stack_cnt += 1;
                                             t2 = newTemp(Ity_I32);
                                             assign(t2, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                             putIReg(30, load(Ity_I32, mkexpr(t2)));
                                          }
                                          // Restore GPR[23]
                                          stack_cnt += 1;
                                          t3 = newTemp(Ity_I32);
                                          assign(t3, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                          putIReg(23, load(Ity_I32, mkexpr(t3)));
                                       }
                                       // Restore GPR[22]
                                       stack_cnt += 1;
                                       t4 = newTemp(Ity_I32);
                                       assign(t4, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                       putIReg(22, load(Ity_I32, mkexpr(t4)));
                                    }
                                    // Restore GPR[21]
                                    stack_cnt += 1;
                                    t5 = newTemp(Ity_I32);
                                    assign(t5, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                    putIReg(21, load(Ity_I32, mkexpr(t5)));
                                 }
                                 // Restore GPR[20]
                                 stack_cnt += 1;
                                 t6 = newTemp(Ity_I32);
                                 assign(t6, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                 putIReg(20, load(Ity_I32, mkexpr(t6)));
                              }
                              // Restore GPR[19]
                              stack_cnt += 1;
                              t7 = newTemp(Ity_I32);
                              assign(t7, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                              putIReg(19, load(Ity_I32, mkexpr(t7)));
                           }
                           // Restore GPR[18]
                           stack_cnt += 1;
                           t8 = newTemp(Ity_I32);
                           assign(t8, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                           putIReg(18, load(Ity_I32, mkexpr(t8)));
                        }
                     }
                     // Restore s0, s1
                     if (svrs_s1) {
                        // Restore GPR[17]
                        stack_cnt += 1;
                        t9 = newTemp(Ity_I32);
                        assign(t9, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        putIReg(17, load(Ity_I32, mkexpr(t9)));
                     }
                     if (svrs_s0) {
                        // Restore GPR[16]
                        stack_cnt += 1;
                        t10 = newTemp(Ity_I32);
                        assign(t10, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        putIReg(16, load(Ity_I32, mkexpr(t10)));
                     }
                     // Restore GPR[4-7]
                     if (extended) {
                        if (svrs_astatic > 0) {
                           // Restore GRP[7]
                           stack_cnt += 1;
                           t11 = newTemp(Ity_I32);
                           assign(t11, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                           putIReg(7, load(Ity_I32, mkexpr(t11)));
                           if (svrs_astatic > 1) {
                              // Restore GPR[6]
                              stack_cnt += 1;
                              t12 = newTemp(Ity_I32);
                              assign(t12, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                              putIReg(6, load(Ity_I32, mkexpr(t12)));
                              if (svrs_astatic > 2) {
                                 // Restore GPR[5]
                                 stack_cnt += 1;
                                 t13 = newTemp(Ity_I32);
                                 assign(t13, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                 putIReg(5, load(Ity_I32, mkexpr(t13)));
                                 if (svrs_astatic > 3) {
                                    // Restore GPR[4]
                                    stack_cnt += 1;
                                    t14 = newTemp(Ity_I32);
                                    assign(t14, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                    putIReg(4, load(Ity_I32, mkexpr(t14)));
                                 }
                              }
                           }
                        }
                     }
                     break;
                  
                  case 1: /* SAVE */
                     stack_cnt = 0;
                     // Save GPR[29] in temp
                     t0 = newTemp(Ity_I32);
                     assign(t0, getIReg(REG_SP));
                     // Save registers GPR[4-7]
                     if (extended) {
                        if (svrs_args > 0) {
                           // Store GRP[4]
                           store(mkexpr(t0), getIReg(4));
                           if (svrs_args > 1) {
                              // Store GPR[5]
                              t1 = newTemp(Ity_I32);
                              assign(t1, binop(Iop_Add32, mkexpr(t0), mkU32(4)));
                              store(mkexpr(t1), getIReg(5));
                              if (svrs_args > 2) {
                                 // Store GPR[6]
                                 t2 = newTemp(Ity_I32);
                                 assign(t2, binop(Iop_Add32, mkexpr(t0), mkU32(8)));
                                 store(mkexpr(t2), getIReg(6));
                                 if (svrs_args > 3) {
                                    // Store GPR[7]
                                    t3 = newTemp(Ity_I32);
                                    assign(t3, binop(Iop_Add32, mkexpr(t0), mkU32(12)));
                                    store(mkexpr(t2), getIReg(7));
                                 }
                              }
                           }
                        }
                     }
                     // Save ra
                     if (svrs_ra) {
                        // Store GPR[31]
                        stack_cnt += 1;
                        t4 = newTemp(Ity_I32);
                        assign(t4, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        store(mkexpr(t4), getIReg(31));
                     }
                     // Save registers GPR[18-23,30]
                     if (extended) {
                        if (svrs_xsregs > 0) {
                           if (svrs_xsregs > 1) {
                              if (svrs_xsregs > 2) {
                                 if (svrs_xsregs > 3) {
                                    if (svrs_xsregs > 4) {
                                       if (svrs_xsregs > 5) {
                                          if (svrs_xsregs > 6) {
                                             // Store GPR[30]
                                             stack_cnt += 1;
                                             t5 = newTemp(Ity_I32);
                                             assign(t5, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                             store(mkexpr(t5), getIReg(30));
                                          }
                                          // Store GPR[23]
                                          stack_cnt += 1;
                                          t6 = newTemp(Ity_I32);
                                          assign(t6, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                          store(mkexpr(t6), getIReg(23));
                                       }
                                       // Store GPR[22]
                                       stack_cnt += 1;
                                       t7 = newTemp(Ity_I32);
                                       assign(t7, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                       store(mkexpr(t7), getIReg(22));
                                    }
                                    // Store GPR[21]
                                    stack_cnt += 1;
                                    t8 = newTemp(Ity_I32);
                                    assign(t8, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                    store(mkexpr(t8), getIReg(21));
                                 }
                                 // Store GPR[20]
                                 stack_cnt += 1;
                                 t9 = newTemp(Ity_I32);
                                 assign(t9, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                 store(mkexpr(t9), getIReg(20));
                              }
                              // Store GPR[19]
                              stack_cnt += 1;
                              t10 = newTemp(Ity_I32);
                              assign(t10, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                              store(mkexpr(t10), getIReg(19));
                           }
                           // Store GPR[18]
                           stack_cnt += 1;
                           t11 = newTemp(Ity_I32);
                           assign(t11, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                           store(mkexpr(t11), getIReg(18));
                        }
                     }
                     // Save s0, s1
                     if (svrs_s1) {
                        // Store GPR[17]
                        stack_cnt += 1;
                        t12 = newTemp(Ity_I32);
                        assign(t12, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        store(mkexpr(t12), getIReg(17));
                     }
                     if (svrs_s0) {
                        // Store GPR[16]
                        stack_cnt += 1;
                        t13 = newTemp(Ity_I32);
                        assign(t13, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                        store(mkexpr(t13), getIReg(16));
                     }
                     // Save GPR[4-7]
                     if (extended) {
                        if (svrs_astatic > 0) {
                           // Store GRP[7]
                           stack_cnt += 1;
                           t14 = newTemp(Ity_I32);
                           assign(t14, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                           store(mkexpr(t14), getIReg(7));
                           if (svrs_astatic > 1) {
                              // Store GPR[6]
                              stack_cnt += 1;
                              t15 = newTemp(Ity_I32);
                              assign(t15, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                              store(mkexpr(t15), getIReg(6));
                              if (svrs_astatic > 2) {
                                 // Store GPR[5]
                                 stack_cnt += 1;
                                 t16 = newTemp(Ity_I32);
                                 assign(t16, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                 store(mkexpr(t16), getIReg(5));
                                 if (svrs_astatic > 3) {
                                    // Store GPR[4]
                                    stack_cnt += 1;
                                    t17 = newTemp(Ity_I32);
                                    assign(t17, binop(Iop_Sub32, mkexpr(t0), mkU32(stack_cnt*4)));
                                    store(mkexpr(t17), getIReg(4));
                                 }
                              }
                           }
                        }
                     }
                     // Adjust stack with framesize.
                     if (extended) {
                        putIReg(29, binop(Iop_Sub32, getIReg(29), mkU32(svrs_framesize << 3)));
                     } else {
                        if (svrs_framesize == 0) {
                           putIReg(29, binop(Iop_Sub32, getIReg(29), mkU32(128)));
                        } else {
                           putIReg(29, binop(Iop_Sub32, getIReg(29), mkU32(svrs_framesize << 3)));
                        }
                     }
                     break;

                  default:
                     goto decode_failure;
               }
               break;

            case 0b101: /* MOV32R */
               rz = (cins & 0x7) >> 0;
               r32 = 0;
               r32 = r32 | (cins & 0x18) >> 3;
               r32 = (r32 << 3) | (cins & 0xE0) >> 5;
               putIReg(r32, getIReg(xlat(rz)));
               break;

            case 0b110: /* Reserved */
               goto decode_failure;

            case 0b111: /* MOVR32 */ /* 16e2 DI DMT DVPE EI EMT EVPE MFC0 MTC0 */
               if (extended) {
                  sel = (cins & 0x1F0000) >> 16;
                  switch (sel) {
                     case 0b00000: /* 16e2 MFC0 */
                        r32 = (cins & 0x1F) >> 0;
                        mfc0_sel = (cins & 0xE00000) >> 21;
                        // Just return 0 for now. Assume CP0 not implemented.
                        putIReg(xlat(ry), mkU32(0));
                        break;

                     case 0b00001: /* 16e2 MTC0 */

                        //break;

                     case 0b00010: /* CLRBIT */

                        //break;

                     case 0b00110: /* CLRBIT_NORES */

                        //break;

                     case 0b00011: /* SETBIT */

                        //break;

                     case 0b00111: /* SETBIT_NORES */

                        //break;

                     default:
                        goto decode_failure;
                  }
               } else {
                  r32 = (cins & 0x1F) >> 0;
                  putIReg(xlat(ry), getIReg(r32));
               }
               break;
            
            default:
               goto decode_failure;
         }         
         break;

		case 0b01101: /* LI */
         if (extended) {
            imm = get_imm_addiu(cins);
            sel = (cins & 0xE0) >> 5;
            switch (sel) {
               case 0b000: /* LI */
                  putIReg(xlat(rx), mkU32(imm));
                  break;
               
               case 0b001: /* 16e2 LUI */
                  putIReg(xlat(rx), mkU32(imm << 16));
                  break;
               
               case 0b010: /* 16e2 ORI */
                  putIReg(xlat(rx), binop(Iop_Or32, getIReg(xlat(rx)), mkU32(imm)));
                  break;
               
               case 0b011: /* 16e2 ANDI */
                  putIReg(xlat(rx), binop(Iop_And32, getIReg(xlat(rx)), mkU32(imm)));
                  break;
               
               case 0b100: /* 16e2 XORI */
                  putIReg(xlat(rx), binop(Iop_Xor32, getIReg(xlat(rx)), mkU32(imm)));
                  break;
               
               case 0b101:
               case 0b110:
               case 0b111:
               default:
                  goto decode_failure;
            }
         } else {
            imm = (cins & 0xFF) >> 0;
            putIReg(xlat(rx), mkU32(imm));
         }
         break;

		case 0b01110: /* CMPI */
         if (extended) {
            imm = get_imm_addiu(cins);
         } else {
            imm = (cins & 0xFF) >> 0;
         }
         putIReg(REG_T8, binop(Iop_Xor32, getIReg(xlat(rx)), mkU32(imm)));
         break;

		case 0b01111: /* Reserved */
         goto decode_failure;

		case 0b10000: /* LB */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = (cins & 0x1F) >> 0;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         putIReg(xlat(ry), unop(Iop_8Sto32, load(Ity_I8, mkexpr(t1))));
         break;

      case 0b10001: /* LH */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0) << 1;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         putIReg(xlat(ry), unop(Iop_16Sto32, load(Ity_I16, mkexpr(t1))));
         break;

      case 0b10010: /* LWSP */ /* 16e2 LB LBU LH LHU LL LW LWL LWR*/
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
            sel = (cins & 0xE0) >> 5;
            switch (sel) {
               case 0b000: /* LW SP-Relative */
                  t1 = newTemp(Ity_I32);
                  assign(t1, binop(Iop_Add32, getIReg(REG_SP), mkU32(imm)));
                  putIReg(xlat(rx), load(Ity_I32, mkexpr(t1)));
                  break;
               
               case 0b001: /* LW GP-Relative */

                  //break;

               case 0b010: /* LH */

                  //break;

               case 0b011: /* LB */

                  //break;

               case 0b100: /* LHU */

                  //break;

               case 0b101: /* LBU */

                  //break;

               case 0b110: /* LL */
                  /* imm value is different */
                  //break;

               case 0b111: /* LWL & LWR */
                  /* imm value is different */
                  //break;

               default:
                  break;
            }
         } else {
            imm = ((cins & 0xFF) >> 0) << 2;
            t1 = newTemp(Ity_I32);
            assign(t1, binop(Iop_Add32, getIReg(REG_SP), mkU32(imm)));
            putIReg(xlat(rx), load(Ity_I32, mkexpr(t1)));
         }
         break;

      case 0b10011: /* LW */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0) << 2;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         putIReg(xlat(ry), load(Ity_I32, mkexpr(t1)));
         break;

      case 0b10100: /* LBU */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = (cins & 0x1F) >> 0;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         putIReg(xlat(ry), unop(Iop_8Uto32, load(Ity_I8, mkexpr(t1))));
         break;

      case 0b10101: /* LHU */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0) << 1;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         putIReg(xlat(ry), unop(Iop_16Uto32, load(Ity_I16, mkexpr(t1))));
         break;

      case 0b10110: /* LWPC */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0xFF) >> 0) << 2;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_And32, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)), mkU32(0xFFFFFFFC)));
         break;

      case 0b10111: /* Reserved */
         goto decode_failure;

      case 0b11000: /* SB */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0);
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         store(mkexpr(t1), narrowTo(Ity_I8, getIReg(xlat(ry))));
         break;

      case 0b11001: /* SH */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0) << 1;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         store(mkexpr(t1), narrowTo(Ity_I16, getIReg(xlat(ry))));
         break;

      case 0b11010: /* SWSP */ /* 16e2 CACHE PREF SB SC SH SW SWL SWR */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
            sel = (cins & 0xE0) >> 5;
            switch (sel) {
               case 0b000: /* SW SP-Relative */
                  t1 = newTemp(Ity_I32);
                  assign(t1, binop(Iop_Add32, getIReg(REG_SP), mkU32(imm)));
                  store(mkexpr(t1), getIReg(xlat(rx)));
                  break;
               
               case 0b001: /* SW GP-Relative */

                  //break;

               case 0b010: /* SH */

                  //break;

               case 0b011: /* SB */

                  //break;

               case 0b100: /* PREF */
                  /* imm value is different */
                  //break;

               case 0b101: /* CACHE */
                  /* imm value is different */
                  //break;

               case 0b110: /* SC */
                  /* imm value is different */
                  //break;

               case 0b111: /* SWL & SWR */
                  /* imm value is different */
                  //break;

               default:
                  break;
            }
         } else {
            imm = ((cins & 0xFF) >> 0) << 2;
            t1 = newTemp(Ity_I32);
            assign(t1, binop(Iop_Add32, getIReg(REG_SP), mkU32(imm)));
            store(mkexpr(t1), getIReg(xlat(rx)));
         }
         break;

      case 0b11011: /* SW */
         if (extended) {
            imm = extend_s_16to32(get_imm_addiu(cins));
         } else {
            imm = ((cins & 0x1F) >> 0) << 2;
         }
         t1 = newTemp(Ity_I32);
         assign(t1, binop(Iop_Add32, getIReg(xlat(rx)), mkU32(imm)));
         store(mkexpr(t1), getIReg(xlat(ry)));
         break;

      case 0b11100: /* RRR */
         /* If extended, the instruction is ASMACRO.
            As not used in firmware, skipping for now. */
         rz = (cins & 0x1C) >> 2;
         rrr_f = (cins & 0x3);
         switch (rrr_f) {
            case 0b00: /* Reserved */
               goto decode_failure;
            
            case 0b01: /* ADDU */
               putIReg(xlat(rz), binop(Iop_Add32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            case 0b10: /* Reserved */
               goto decode_failure;
            
            case 0b11: /* SUBU */
               putIReg(xlat(rz), binop(Iop_Sub32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            default:
               goto decode_failure;
         }

         break;

      case 0b11101: /* RR */
         rr_funct = (cins & 0x1F) >> 0;
         switch (rr_funct) {
            case 0b00000: /* J(AL)R(C) */
               switch (ry) {
                  case 0b000: /* JR rx */
                     /* Handles ISA Mode bit. (need to do) */
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(xlat(rx))));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(xlat(rx)) & 0x1;
                     break;
                  
                  case 0b001: /* JR ra */
                     /* This too with ISA Mode. */
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(REG_RA)));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(REG_RA) & 0x1;
                     break;
                  
                  case 0b010: /* JALR */
                     putIReg(31, mkU32(guest_PC_curr_instr + 4));
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(xlat(rx))));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(xlat(rx)) & 0x1;
                     break;
                  
                  case 0b011: /* Reserved */
                     goto decode_failure;
                  
                  case 0b100: /* JRC rx */
                     /* JR rx with no delay slot. */
                     /* Handles ISA Mode bit. (need to do) */
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(xlat(rx))));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(xlat(rx)) & 0x1;
                     compact = True;
                     break;
                  
                  case 0b101: /* JRC ra */
                     /* This too with ISA Mode. */
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(REG_RA)));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(REG_RA) & 0x1;
                     compact = True;
                     break;
                  
                  case 0b110: /* JALRC */
                     putIReg(31, mkU32(guest_PC_curr_instr + 4));
                     t0 = newTemp(Ity_I32);
                     assign(t0, binop(Iop_And32, mkU32(0xFFFFFFFE), getIReg(xlat(rx))));
                     lastn = mkexpr(t0);
                     // ISA_Mode = getIReg(xlat(rx)) & 0x1;
                     compact = True;
                     break;
                  
                  case 0b111: /* Reserved */
                  default:
                     goto decode_failure;
               }
               break;
            
            case 0b00001: /* SDBBP */
               /* Software Debug Breakpoint */
               /* Do we need this..? */
               goto decode_failure;
               //break;
            
            case 0b00010: /* SLT */
               putIReg(REG_T8, unop(Iop_1Uto32, binop(Iop_CmpLT32S, getIReg(xlat(rx)), getIReg(xlat(ry)))));
               break;
            
            case 0b00011: /* SLTU */
               putIReg(REG_T8, unop(Iop_1Uto32, binop(Iop_CmpLT32U, getIReg(xlat(rx)), getIReg(xlat(ry)))));
               break;
            
            case 0b00100: /* SLLV */
               rd = xlat(ry);
               rt = xlat(ry);
               rs = xlat(rx);
               SXXV_PATTERN(Iop_Shl32);
               break;
            
            case 0b00101: /* BREAK */
               jmp_lit32(&dres, Ijk_SigTRAP, (guest_PC_curr_instr + dres_len));
               vassert(dres.whatNext == Dis_StopHere);
               break;
            
            case 0b00110: /* SRLV */
               rd = xlat(ry);
               rt = xlat(ry);
               rs = xlat(rx);
               SXXV_PATTERN(Iop_Shr32);
               break;
            
            case 0b00111: /* SRAV */
               rd = xlat(ry);
               rt = xlat(ry);
               rs = xlat(rx);
               SXXV_PATTERN(Iop_Sar32);
               break;
            
            case 0b01000: /* Reserved */
            case 0b01001: /* Reserved */
               goto decode_failure;
            
            case 0b01010: /* CMP */
               putIReg(REG_T8, binop(Iop_Xor32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            case 0b01011: /* NEG */
               putIReg(xlat(rx), binop(Iop_Sub32, getIReg(0), getIReg(xlat(ry))));
               break;
            
            case 0b01100: /* AND */
               putIReg(xlat(rx), binop(Iop_And32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            case 0b01101: /* OR */
               putIReg(xlat(rx), binop(Iop_Or32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            case 0b01110: /* XOR */
               putIReg(xlat(rx), binop(Iop_Xor32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               break;
            
            case 0b01111: /* NOT */
               putIReg(xlat(rx), binop(Iop_Xor32, getIReg(xlat(ry)), mkU32(0xFFFFFFFF)));
               break;
            
            case 0b10000: /* MFHI */
               putIReg(xlat(rx), getHI());
               break;
            
            case 0b10001: /* CNVT */
               switch (ry) {
                  case 0b000: /* ZEB */
                     putIReg(xlat(rx), binop(Iop_And32, getIReg(xlat(rx)), mkU32(0xFF)));
                     break;
                  
                  case 0b001: /* ZEH */
                     putIReg(xlat(rx), binop(Iop_And32, getIReg(xlat(rx)), mkU32(0xFFFF)));
                     break;
                  
                  case 0b010:
                  case 0b011:
                     goto decode_failure;

                  case 0b100: /* SEB */
                     putIReg(xlat(rx), unop(Iop_8Sto32, unop(Iop_32to8, getIReg(xlat(rx)))));
                     break;
                  
                  case 0b101: /* SEH */
                     putIReg(xlat(rx), unop(Iop_16Sto32, unop(Iop_32to16, getIReg(xlat(rx)))));
                     break;
                  
                  case 0b110:
                  case 0b111:
                  default:
                     goto decode_failure;
               }
               break;

            case 0b10010: /* MFLO */
               putIReg(xlat(rx), getLO());
               break;
            
            case 0b10011: /* Reserved */
            case 0b10100: /* Reserved */
            case 0b10101: /* Reserved */
            case 0b10110: /* Reserved */
            case 0b10111: /* Reserved */
               goto decode_failure;

            case 0b11000: /* MULT */
               t1 = newTemp(Ity_I64);
               assign(t1, binop(Iop_MullS32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               e = mkexpr(t1);
               putLO(unop(Iop_64to32, e));
               putHI(unop(Iop_64HIto32, e));
               break;
            
            case 0b11001: /* MULTU */
               t1 = newTemp(Ity_I64);
               assign(t1, binop(Iop_MullU32, getIReg(xlat(rx)), getIReg(xlat(ry))));
               e = mkexpr(t1);
               putLO(unop(Iop_64to32, e));
               putHI(unop(Iop_64HIto32, e));
               break;
            
            case 0b11010: /* DIV */
               t1 = newTemp(Ity_I64);
               t2 = newTemp(Ity_I64);

               assign(t1, unop(Iop_32Sto64, getIReg(xlat(rx))));
               assign(t2, binop(Iop_DivModS64to32, mkexpr(t1), getIReg(xlat(ry))));

               putHI(unop(Iop_64HIto32, mkexpr(t2)));
               putLO(unop(Iop_64to32, mkexpr(t2)));
               break;
            
            case 0b11011: /* DIVU */
               t1 = newTemp(Ity_I64);
               t2 = newTemp(Ity_I64);

               assign(t1, unop(Iop_32Sto64, getIReg(xlat(rx))));
               assign(t2, binop(Iop_DivModU64to32, mkexpr(t1), getIReg(xlat(ry))));

               putHI(unop(Iop_64HIto32, mkexpr(t2)));
               putLO(unop(Iop_64to32, mkexpr(t2)));
               break;
            
            case 0b11100: /* Reserved */
            case 0b11101: /* Reserved */
            case 0b11110: /* Reserved */
            case 0b11111: /* Reserved */
            default:
               goto decode_failure;
         }
         break;

      case 0b11110: /* EXTEND */
         /* Shouldn't arrive here. */
         goto decode_failure;

      case 0b11111: /* Reserved */
         goto decode_failure;

		default:
			goto decode_failure;

decode_failure:

         DIP("vex mips->IR: unhandled instruction bytes: 0x%x 0x%x 0x%x 0x%x\n",
							(UInt) getIByte(delta_start + 0),
							(UInt) getIByte(delta_start + 1),
							(UInt) getIByte(delta_start + 2),
							(UInt) getIByte(delta_start + 3));
			/* All decode failures end up here. */
			if (sigill_diag)
				vex_printf("vex mips->IR: unhandled instruction bytes: "
							"0x%x 0x%x 0x%x 0x%x\n",
							(UInt) getIByte(delta_start + 0),
							(UInt) getIByte(delta_start + 1),
							(UInt) getIByte(delta_start + 2),
							(UInt) getIByte(delta_start + 3));

			/* Tell the dispatcher that this insn cannot be decoded, and so has
				not been executed, and (is currently) the next to be executed.
				EIP should be up-to-date since it made so at the start bnezof each
				insn, but nevertheless be paranoid and update it again right
				now. */
			stmt(IRStmt_Put(offsetof(VexGuestMIPS32State, guest_PC),
					mkU32(guest_PC_curr_instr)));
			jmp_lit32(&dres, Ijk_NoDecode, guest_PC_curr_instr);

			dres.whatNext = Dis_StopHere;
			dres.len = 0;
			return dres;
   }  /* switch (opc) for the main (primary) opcode switch. */

   if (delay_slot_branch) {
      Bool is_branch;
      delay_slot_branch = False;
      stmt(bstmt);
      bstmt = NULL;
      putPC(mkU32(guest_PC_curr_instr + dres_len));
      is_branch = is_Branch_or_Jump_and_Link(guest_code + delta - prev_dres_len);
      if(is_branch) {
          dres.jk_StopHere = Ijk_Call;
      } else {
          dres.jk_StopHere = is_Ret(guest_code + delta - prev_dres_len)?
                             Ijk_Ret : Ijk_Boring;
      }
   }

   if (delay_slot_jump) {
      Bool is_branch;
      putPC(lastn);
      lastn = NULL;
      is_branch = is_Branch_or_Jump_and_Link(guest_code + delta - prev_dres_len);
      if(is_branch) {
          dres.jk_StopHere = Ijk_Call;
      } else {
          dres.jk_StopHere = is_Ret(guest_code + delta - prev_dres_len)?
                             Ijk_Ret : Ijk_Boring;
      }
   }

   if (compact) {
      Bool is_branch;
      putPC(lastn);
      lastn = NULL;
      is_branch = is_Branch_or_Jump_and_Link(guest_code + delta);
      if(is_branch) {
          dres.jk_StopHere = Ijk_Call;
      } else {
          dres.jk_StopHere = is_Ret(guest_code + delta)?
                             Ijk_Ret : Ijk_Boring;
      }
      dres.whatNext = Dis_StopHere;
   }

decode_success:
   /* All decode successes end up here. */
   switch (dres.whatNext) {
      case Dis_Continue:
         putPC(mkU32(guest_PC_curr_instr + dres_len));
         break;
      case Dis_ResteerU:
      case Dis_ResteerC:
         putPC(mkU32(dres.continueAt));
         break;
      case Dis_StopHere:
         break;
      default:
         vassert(0);
         break;
   }

   /* On MIPS we need to check if the last instruction in block is branch or
      jump. Do this by first checking if we just disassembled the second-last
      instruction in the block, and we're not stopping here. */
   
   /* This is a problem,, How are we going to know the number of total instructions */
   
   // Just not using max_insns and max_bytes seems right.
   // Commenting out temporarily.

   /*if ((((delta / 4) == vex_control.guest_max_insns - 2) ||
       delta == vex_control.guest_max_bytes - 8) &&
       (dres.whatNext != Dis_StopHere)) {
      if (branch_or_jump(guest_code + delta + dres.len)) {
         dres.whatNext = Dis_StopHere;
         dres.jk_StopHere = Ijk_Boring;
         putPC(mkU32(guest_PC_curr_instr + dres.len));
      }
   }*/
   
   dres.len = dres_len;

   DIP("\n");

   return dres;

}

/*------------------------------------------------------------*/
/*--- Top-level fn                                         ---*/
/*------------------------------------------------------------*/

/* Disassemble a single instruction into IR.  The instruction
   is located in host memory at &guest_code[delta]. */
DisResult disInstr_MIPS16e2( IRSB*        irsb_IN,
                         Bool         (*resteerOkFn) ( void *, Addr ),
                         Bool         resteerCisOk,
                         void*        callback_opaque,
                         const UChar* guest_code_IN,
                         Long         delta,
                         Addr         guest_IP,
                         VexArch      guest_arch,
                         const VexArchInfo* archinfo,
                         const VexAbiInfo*  abiinfo,
                         VexEndness   host_endness_IN,
                         Bool         sigill_diag_IN )
{
   DisResult dres;
   /* Set globals (see top of this file) */
   vassert(guest_arch == VexArchMIPS16e2);

   guest_code = guest_code_IN;
   irsb = irsb_IN;
   host_endness = host_endness_IN;
   guest_endness = archinfo->endness == VexEndnessLE ? Iend_LE : Iend_BE;
   guest_PC_curr_instr = (Addr64)guest_IP;

   dres = disInstr_MIPS16e2_WRK(resteerOkFn, resteerCisOk, callback_opaque,
                            delta, archinfo, abiinfo, sigill_diag_IN);

   return dres;
}

/*--------------------------------------------------------------------*/
/*--- end                                    guest_mips16e2_toIR.c ---*/
/*--------------------------------------------------------------------*/
