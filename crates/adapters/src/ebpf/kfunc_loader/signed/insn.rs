//! A small eBPF assembler: the instructions the loader generator emits, each
//! as the little-endian `u64` the kernel reads, with forward labels resolved
//! once the program is complete.

/// `BPF_ALU64 | BPF_MOV | BPF_K`.
pub(super) const MOV64_IMM: u8 = 0xb7;
/// `BPF_ALU64 | BPF_MOV | BPF_X`.
const MOV64_REG: u8 = 0xbf;
/// `BPF_ALU64 | BPF_ADD | BPF_K`.
const ADD64_IMM: u8 = 0x07;
/// `BPF_ALU64 | BPF_RSH | BPF_K`.
const RSH64_IMM: u8 = 0x77;
/// `BPF_ALU64 | BPF_LSH | BPF_K`.
const LSH64_IMM: u8 = 0x67;
/// `BPF_ALU64 | BPF_AND | BPF_K`.
const AND64_IMM: u8 = 0x57;
/// `BPF_ALU64 | BPF_OR | BPF_K`.
const OR64_IMM: u8 = 0x47;
/// `BPF_LD | BPF_IMM | BPF_DW`, the first half of a 64-bit load.
pub(super) const LD_IMM64: u8 = 0x18;
/// `BPF_LDX | BPF_MEM | BPF_DW`.
const LDX_DW: u8 = 0x79;
/// `BPF_LDX | BPF_MEM | BPF_W`.
const LDX_W: u8 = 0x61;
/// `BPF_STX | BPF_MEM | BPF_DW`.
const STX_DW: u8 = 0x7b;
/// `BPF_STX | BPF_MEM | BPF_W`.
const STX_W: u8 = 0x63;
/// `BPF_ST | BPF_MEM | BPF_DW`.
const ST_DW: u8 = 0x7a;
/// `BPF_ST | BPF_MEM | BPF_W`.
const ST_W: u8 = 0x62;
/// `BPF_JMP | BPF_JNE | BPF_X`.
const JNE_REG: u8 = 0x5d;
/// `BPF_JMP | BPF_JNE | BPF_K`.
const JNE_IMM: u8 = 0x55;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
const JEQ_IMM: u8 = 0x15;
/// `BPF_JMP | BPF_JSGT | BPF_K`.
const JSGT_IMM: u8 = 0x65;
/// `BPF_JMP | BPF_JA`.
const JA: u8 = 0x05;
/// `BPF_JMP | BPF_CALL`.
pub(super) const CALL: u8 = 0x85;
/// `BPF_JMP | BPF_EXIT`.
pub(super) const EXIT: u8 = 0x95;

/// `BPF_PSEUDO_MAP_IDX`: `imm` indexes the load's `fd_array`, and the
/// register gets the map itself.
pub(super) const PSEUDO_MAP_IDX: u8 = 5;
/// `BPF_PSEUDO_MAP_IDX_VALUE`: `imm` indexes the load's `fd_array`, the
/// second half's `imm` is an offset, and the register gets a pointer into
/// the map's value.
pub(super) const PSEUDO_MAP_IDX_VALUE: u8 = 6;

/// The frame pointer.
pub(super) const R10: u8 = 10;

/// One encoded instruction.
#[must_use]
pub(super) fn encode(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    u64::from(code)
        | (u64::from(dst & 0x0f) << 8)
        | (u64::from(src & 0x0f) << 12)
        | (u64::from(off.cast_unsigned()) << 16)
        | (u64::from(imm.cast_unsigned()) << 32)
}

/// The opcode of an encoded instruction.
#[must_use]
pub(super) fn code(insn: u64) -> u8 {
    (insn & 0xff) as u8
}

/// The destination register of an encoded instruction.
#[must_use]
pub(super) fn dst(insn: u64) -> u8 {
    ((insn >> 8) & 0x0f) as u8
}

/// The source register of an encoded instruction.
#[must_use]
pub(super) fn src(insn: u64) -> u8 {
    ((insn >> 12) & 0x0f) as u8
}

/// The `imm` of an encoded instruction.
#[must_use]
pub(super) fn imm(insn: u64) -> i32 {
    ((insn >> 32) as u32).cast_signed()
}

/// The `off` of an encoded instruction.
#[must_use]
pub(super) fn off(insn: u64) -> i16 {
    (((insn >> 16) & 0xffff) as u16).cast_signed()
}

/// A forward or backward jump target, bound with [`Asm::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Label(usize);

/// A program under construction.
#[derive(Debug, Default)]
pub(super) struct Asm {
    insns: Vec<u64>,
    labels: Vec<Option<usize>>,
    /// `(instruction index, label)` for every jump still to resolve.
    fixups: Vec<(usize, Label)>,
}

impl Asm {
    /// A fresh label, bound later.
    pub(super) fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    /// Bind `label` to the next instruction.
    pub(super) fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.insns.len());
    }

    fn push(&mut self, insn: u64) {
        self.insns.push(insn);
    }

    fn jump(&mut self, code: u8, dst: u8, src: u8, imm: i32, to: Label) {
        self.fixups.push((self.insns.len(), to));
        self.push(encode(code, dst, src, 0, imm));
    }

    pub(super) fn mov_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(MOV64_IMM, dst, 0, 0, imm));
    }

    pub(super) fn mov_reg(&mut self, dst: u8, src: u8) {
        self.push(encode(MOV64_REG, dst, src, 0, 0));
    }

    pub(super) fn add_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(ADD64_IMM, dst, 0, 0, imm));
    }

    pub(super) fn rsh_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(RSH64_IMM, dst, 0, 0, imm));
    }

    pub(super) fn lsh_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(LSH64_IMM, dst, 0, 0, imm));
    }

    pub(super) fn and_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(AND64_IMM, dst, 0, 0, imm));
    }

    pub(super) fn or_imm(&mut self, dst: u8, imm: i32) {
        self.push(encode(OR64_IMM, dst, 0, 0, imm));
    }

    /// `dst = value`, a 64-bit constant in two instructions.
    pub(super) fn ld_imm64(&mut self, dst: u8, value: u64) {
        self.push(encode(LD_IMM64, dst, 0, 0, (value as u32).cast_signed()));
        self.push(encode(0, 0, 0, 0, ((value >> 32) as u32).cast_signed()));
    }

    /// `dst = &fd_array[map_idx]` (`value_off` `None`), or a pointer
    /// `value_off` bytes into that map's value.
    pub(super) fn ld_map(&mut self, dst: u8, map_idx: i32, value_off: Option<i32>) {
        let (kind, second) = match value_off {
            None => (PSEUDO_MAP_IDX, 0),
            Some(off) => (PSEUDO_MAP_IDX_VALUE, off),
        };
        self.push(encode(LD_IMM64, dst, kind, 0, map_idx));
        self.push(encode(0, 0, 0, 0, second));
    }

    pub(super) fn ldx_dw(&mut self, dst: u8, src: u8, off: i16) {
        self.push(encode(LDX_DW, dst, src, off, 0));
    }

    pub(super) fn ldx_w(&mut self, dst: u8, src: u8, off: i16) {
        self.push(encode(LDX_W, dst, src, off, 0));
    }

    pub(super) fn stx_dw(&mut self, dst: u8, off: i16, src: u8) {
        self.push(encode(STX_DW, dst, src, off, 0));
    }

    pub(super) fn stx_w(&mut self, dst: u8, off: i16, src: u8) {
        self.push(encode(STX_W, dst, src, off, 0));
    }

    pub(super) fn st_dw(&mut self, dst: u8, off: i16, imm: i32) {
        self.push(encode(ST_DW, dst, 0, off, imm));
    }

    pub(super) fn st_w(&mut self, dst: u8, off: i16, imm: i32) {
        self.push(encode(ST_W, dst, 0, off, imm));
    }

    pub(super) fn jne_reg(&mut self, dst: u8, src: u8, to: Label) {
        self.jump(JNE_REG, dst, src, 0, to);
    }

    pub(super) fn jne_imm(&mut self, dst: u8, imm: i32, to: Label) {
        self.jump(JNE_IMM, dst, 0, imm, to);
    }

    pub(super) fn jeq_imm(&mut self, dst: u8, imm: i32, to: Label) {
        self.jump(JEQ_IMM, dst, 0, imm, to);
    }

    pub(super) fn jsgt_imm(&mut self, dst: u8, imm: i32, to: Label) {
        self.jump(JSGT_IMM, dst, 0, imm, to);
    }

    pub(super) fn ja(&mut self, to: Label) {
        self.jump(JA, 0, 0, 0, to);
    }

    pub(super) fn call(&mut self, helper: i32) {
        self.push(encode(CALL, 0, 0, 0, helper));
    }

    pub(super) fn exit(&mut self) {
        self.push(encode(EXIT, 0, 0, 0, 0));
    }

    /// The finished program, every jump pointed at its label.
    ///
    /// # Errors
    ///
    /// A label was never bound, or a jump is further than `off` reaches.
    pub(super) fn finish(mut self) -> Result<Vec<u64>, String> {
        for (at, label) in std::mem::take(&mut self.fixups) {
            let target =
                self.labels[label.0].ok_or_else(|| format!("label {} unbound", label.0))?;
            let delta = i64::try_from(target).map_err(|e| e.to_string())?
                - i64::try_from(at).map_err(|e| e.to_string())?
                - 1;
            let delta =
                i16::try_from(delta).map_err(|_| format!("jump of {delta} out of range"))?;
            let insn = self.insns[at];
            self.insns[at] = (insn & !(0xffff << 16)) | (u64::from(delta.cast_unsigned()) << 16);
        }
        Ok(self.insns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instruction_is_laid_out_the_way_the_kernel_reads_it() {
        let insn = encode(0x85, 0, 2, 3, 0x1234);
        assert_eq!(insn & 0xff, 0x85);
        assert_eq!((insn >> 8) & 0xff, 0x20);
        assert_eq!(off(insn), 3);
        assert_eq!(imm(insn), 0x1234);
        assert_eq!(src(insn), 2);
    }

    #[test]
    fn a_forward_jump_lands_after_the_skipped_instructions() {
        let mut asm = Asm::default();
        let end = asm.label();
        asm.jeq_imm(1, 0, end);
        asm.mov_imm(0, 1);
        asm.mov_imm(0, 2);
        asm.bind(end);
        asm.exit();
        let prog = asm.finish().expect("bound");
        assert_eq!(off(prog[0]), 2);
    }

    #[test]
    fn a_map_value_load_names_the_slot_and_the_offset() {
        let mut asm = Asm::default();
        asm.ld_map(2, 0, Some(40));
        let prog = asm.finish().expect("no jumps");
        assert_eq!(code(prog[0]), LD_IMM64);
        assert_eq!(src(prog[0]), PSEUDO_MAP_IDX_VALUE);
        assert_eq!(imm(prog[0]), 0);
        assert_eq!(imm(prog[1]), 40);
    }

    #[test]
    fn an_unbound_label_is_refused() {
        let mut asm = Asm::default();
        let nowhere = asm.label();
        asm.ja(nowhere);
        assert!(asm.finish().is_err());
    }

    #[test]
    fn a_wide_constant_is_split_low_then_high() {
        let mut asm = Asm::default();
        asm.ld_imm64(3, 0x1122_3344_5566_7788);
        let prog = asm.finish().expect("no jumps");
        assert_eq!(imm(prog[0]).cast_unsigned(), 0x5566_7788);
        assert_eq!(imm(prog[1]).cast_unsigned(), 0x1122_3344);
    }
}
