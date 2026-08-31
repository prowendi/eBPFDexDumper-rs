//! Minimal DEX bytecode walker.
//!
//! The dumper captures a method's `insns` array straight out of ART's in-memory
//! CodeItem (`read_method_bytecode` in `bpf/bpf.c` reads `insns_size * 2` bytes
//! from `code_item + insns_offset`) and nothing else — no `registers_size`, no
//! `ins_size`, no try/catch table. To wrap such a blob back into a standalone
//! `code_item` we have to recover the register window ourselves, and the only
//! way to do that is to walk the instruction stream.
//!
//! So this module implements exactly what synthesis needs: instruction widths,
//! so we can advance; and the register / outgoing-argument high-water marks, so
//! the synthesized header covers every register the code touches. Nothing here
//! decodes operands into a usable IR.

/// Result of walking an `insns` stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InsnScan {
    /// One past the highest register index the stream touches, counting the
    /// high half of every wide (`vN`/`vN+1`) operand. Zero when no instruction
    /// names a register.
    pub registers_used: u16,
    /// Widest outgoing-argument window any invoke-style instruction needs.
    pub outs_size: u16,
    /// Code units consumed. Equal to the whole stream after a clean walk; on
    /// failure it marks where decoding gave up.
    pub units_walked: usize,
}

/// A walk that stopped early, carrying how far it got. Callers that would
/// rather emit an approximate header than drop the method can still use
/// `scan` — see `--force-mismatch` in the repair path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialScan {
    pub scan: InsnScan,
    pub error: BytecodeError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BytecodeError {
    #[error("insns length {0} is not a whole number of 16-bit code units")]
    OddLength(usize),
    #[error("unknown opcode 0x{op:02x} at code unit {pos}")]
    UnknownOpcode { op: u8, pos: usize },
    #[error("instruction at code unit {pos} runs past the end of the stream")]
    Truncated { pos: usize },
    #[error("unknown payload ident 0x{ident:04x} at code unit {pos}")]
    UnknownPayload { ident: u16, pos: usize },
    #[error("instruction at code unit {pos} declares {count} argument registers (max 5)")]
    BadArgCount { pos: usize, count: u8 },
    #[error("register index at code unit {pos} does not fit in 16 bits")]
    RegisterOverflow { pos: usize },
}

/// Where an instruction format keeps its register operands.
///
/// Formats that differ only in total width share a variant — width is tracked
/// separately in [`format_of`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operands {
    /// 10x / 10t / 20t / 30t — no register operands.
    NoRegs,
    /// 12x / 22t / 22s / 22c — `vA` is the low nibble of byte 1, `vB` the high.
    NibbleAb,
    /// 11n — `vA` is the low nibble of byte 1.
    NibbleA,
    /// 11x / 21t / 21s / 21h / 21c / 31i / 31t / 31c / 51l — `vA` is byte 1.
    ByteA,
    /// 22x — `vA` is byte 1, `vB` is code unit 1.
    ByteAUnitB,
    /// 23x — `vA` is byte 1, `vB` and `vC` are the low and high bytes of unit 1.
    ByteABytesBc,
    /// 22b — `vA` is byte 1, `vB` is the low byte of unit 1 (high byte is a literal).
    ByteAByteB,
    /// 32x — `vA` and `vB` are code units 1 and 2.
    UnitAUnitB,
    /// 35c / 45cc — up to five individually listed argument registers.
    Args35c,
    /// 3rc / 4rcc — a contiguous run of argument registers.
    Args3rc,
}

/// Width in 16-bit code units and register layout for `op`, or `None` for the
/// opcodes the DEX spec leaves unused.
const fn format_of(op: u8) -> Option<(usize, Operands)> {
    use Operands::{
        Args35c, Args3rc, ByteA, ByteAByteB, ByteABytesBc, ByteAUnitB, NibbleA, NibbleAb, NoRegs,
        UnitAUnitB,
    };
    Some(match op {
        0x00 => (1, NoRegs),              // nop (payload idents handled by the walker)
        0x01 => (1, NibbleAb),            // move
        0x02 => (2, ByteAUnitB),          // move/from16
        0x03 => (3, UnitAUnitB),          // move/16
        0x04 => (1, NibbleAb),            // move-wide
        0x05 => (2, ByteAUnitB),          // move-wide/from16
        0x06 => (3, UnitAUnitB),          // move-wide/16
        0x07 => (1, NibbleAb),            // move-object
        0x08 => (2, ByteAUnitB),          // move-object/from16
        0x09 => (3, UnitAUnitB),          // move-object/16
        0x0a..=0x0d => (1, ByteA),        // move-result{,-wide,-object}, move-exception
        0x0e => (1, NoRegs),              // return-void
        0x0f..=0x11 => (1, ByteA),        // return{,-wide,-object}
        0x12 => (1, NibbleA),             // const/4
        0x13 => (2, ByteA),               // const/16
        0x14 => (3, ByteA),               // const
        0x15 => (2, ByteA),               // const/high16
        0x16 => (2, ByteA),               // const-wide/16
        0x17 => (3, ByteA),               // const-wide/32
        0x18 => (5, ByteA),               // const-wide
        0x19 => (2, ByteA),               // const-wide/high16
        0x1a => (2, ByteA),               // const-string
        0x1b => (3, ByteA),               // const-string/jumbo
        0x1c => (2, ByteA),               // const-class
        0x1d..=0x1e => (1, ByteA),        // monitor-enter, monitor-exit
        0x1f => (2, ByteA),               // check-cast
        0x20 => (2, NibbleAb),            // instance-of
        0x21 => (1, NibbleAb),            // array-length
        0x22 => (2, ByteA),               // new-instance
        0x23 => (2, NibbleAb),            // new-array
        0x24 => (3, Args35c),             // filled-new-array
        0x25 => (3, Args3rc),             // filled-new-array/range
        0x26 => (3, ByteA),               // fill-array-data
        0x27 => (1, ByteA),               // throw
        0x28 => (1, NoRegs),              // goto
        0x29 => (2, NoRegs),              // goto/16
        0x2a => (3, NoRegs),              // goto/32
        0x2b..=0x2c => (3, ByteA),        // packed-switch, sparse-switch
        0x2d..=0x31 => (2, ByteABytesBc), // cmpl/cmpg-float, cmpl/cmpg-double, cmp-long
        0x32..=0x37 => (2, NibbleAb),     // if-eq .. if-le
        0x38..=0x3d => (2, ByteA),        // if-eqz .. if-lez
        0x44..=0x51 => (2, ByteABytesBc), // aget* / aput*
        0x52..=0x5f => (2, NibbleAb),     // iget* / iput*
        0x60..=0x6d => (2, ByteA),        // sget* / sput*
        0x6e..=0x72 => (3, Args35c),      // invoke-virtual .. invoke-interface
        0x74..=0x78 => (3, Args3rc),      // invoke-*/range
        0x7b..=0x8f => (1, NibbleAb),     // neg-int .. int-to-short
        0x90..=0xaf => (2, ByteABytesBc), // add-int .. rem-double
        0xb0..=0xcf => (1, NibbleAb),     // add-int/2addr .. rem-double/2addr
        0xd0..=0xd7 => (2, NibbleAb),     // add-int/lit16 .. rsub-int/lit16
        0xd8..=0xe2 => (2, ByteAByteB),   // add-int/lit8 .. ushr-int/lit8
        0xfa => (4, Args35c),             // invoke-polymorphic
        0xfb => (4, Args3rc),             // invoke-polymorphic/range
        0xfc => (3, Args35c),             // invoke-custom
        0xfd => (3, Args3rc),             // invoke-custom/range
        0xfe => (2, ByteA),               // const-method-handle
        0xff => (2, ByteA),               // const-method-type
        // 0x3e..=0x43, 0x73, 0x79..=0x7a and 0xe3..=0xf9 are unused. Hitting one
        // means the stream is not real bytecode, so refuse rather than guess.
        _ => return None,
    })
}

/// Which operand slots of `op` name a register *pair* (`vN` plus `vN+1`).
/// Bit 0 is `vA`, bit 1 is `vB`, bit 2 is `vC`.
///
/// Wide operands only ever name their low half, so without this the walker
/// would undercount `registers_used` by one for any method whose top register
/// is the high half of a long or double.
const fn wide_slots(op: u8) -> u8 {
    match op {
        0x04..=0x06 => 0b011,        // move-wide{,/from16,/16}
        0x0b => 0b001,               // move-result-wide
        0x10 => 0b001,               // return-wide
        0x16..=0x19 => 0b001,        // const-wide{/16,/32,,/high16}
        0x2f..=0x31 => 0b110,        // cmpl-double, cmpg-double, cmp-long
        0x45 => 0b001,               // aget-wide
        0x4c => 0b001,               // aput-wide
        0x53 => 0b001,               // iget-wide
        0x5a => 0b001,               // iput-wide
        0x61 => 0b001,               // sget-wide
        0x68 => 0b001,               // sput-wide
        0x7d | 0x7e | 0x80 => 0b011, // neg-long, not-long, neg-double
        0x81 | 0x83 => 0b001,        // int-to-long, int-to-double
        0x84 | 0x85 => 0b010,        // long-to-int, long-to-float
        0x86 => 0b011,               // long-to-double
        0x88 | 0x89 => 0b001,        // float-to-long, float-to-double
        0x8a | 0x8c => 0b010,        // double-to-int, double-to-float
        0x8b => 0b011,               // double-to-long
        0x9b..=0xa2 => 0b111,        // add/sub/mul/div/rem/and/or/xor-long
        0xa3..=0xa5 => 0b011,        // shl/shr/ushr-long (the shift distance is narrow)
        0xab..=0xaf => 0b111,        // add/sub/mul/div/rem-double
        0xbb..=0xc2 => 0b011,        // *-long/2addr
        0xc3..=0xc5 => 0b001,        // sh*-long/2addr (the shift distance is narrow)
        0xcb..=0xcf => 0b011,        // *-double/2addr
        _ => 0,
    }
}

/// Walk `insns` and report the register window it needs.
///
/// `Err` carries the partial scan alongside the reason the walk stopped, so a
/// caller can choose between dropping the method and emitting a best-effort
/// header.
pub fn scan_insns(insns: &[u8]) -> Result<InsnScan, PartialScan> {
    let units = insns.len() / 2;
    if units * 2 != insns.len() {
        return Err(PartialScan {
            scan: InsnScan::default(),
            error: BytecodeError::OddLength(insns.len()),
        });
    }

    let unit = |i: usize| u16::from_le_bytes([insns[i * 2], insns[i * 2 + 1]]);

    let mut max_reg: u32 = 0;
    let mut outs: u32 = 0;
    let mut pos = 0usize;

    macro_rules! fail {
        ($err:expr) => {
            return Err(PartialScan {
                scan: InsnScan {
                    registers_used: max_reg.min(u32::from(u16::MAX)) as u16,
                    outs_size: outs.min(u32::from(u16::MAX)) as u16,
                    units_walked: pos,
                },
                error: $err,
            })
        };
    }

    while pos < units {
        let unit0 = unit(pos);
        let op = (unit0 & 0xff) as u8;
        let byte1 = u32::from(unit0 >> 8);

        // A zero opcode with a non-zero high byte is a switch or array-data
        // payload spliced into the stream, not an instruction.
        if op == 0x00 && unit0 != 0 {
            let width = match payload_units(insns, units, pos, unit0) {
                Ok(width) => width,
                Err(err) => fail!(err),
            };
            pos += width;
            continue;
        }

        let Some((width, regs)) = format_of(op) else {
            fail!(BytecodeError::UnknownOpcode { op, pos })
        };
        if units - pos < width {
            fail!(BytecodeError::Truncated { pos })
        }

        let wide = wide_slots(op);
        let mut note = |reg: u32, slot: u8| {
            let top = reg + if wide & slot != 0 { 2 } else { 1 };
            if top > max_reg {
                max_reg = top;
            }
        };

        match regs {
            Operands::NoRegs => {}
            Operands::NibbleAb => {
                note(byte1 & 0xf, 0b001);
                note(byte1 >> 4, 0b010);
            }
            Operands::NibbleA => note(byte1 & 0xf, 0b001),
            Operands::ByteA => note(byte1, 0b001),
            Operands::ByteAUnitB => {
                note(byte1, 0b001);
                note(u32::from(unit(pos + 1)), 0b010);
            }
            Operands::ByteABytesBc => {
                let bc = unit(pos + 1);
                note(byte1, 0b001);
                note(u32::from(bc & 0xff), 0b010);
                note(u32::from(bc >> 8), 0b100);
            }
            Operands::ByteAByteB => {
                note(byte1, 0b001);
                note(u32::from(unit(pos + 1) & 0xff), 0b010);
            }
            Operands::UnitAUnitB => {
                note(u32::from(unit(pos + 1)), 0b001);
                note(u32::from(unit(pos + 2)), 0b010);
            }
            Operands::Args35c => {
                // [A|G|op] [BBBB] [F|E|D|C]: A argument registers drawn from
                // C, D, E, F, G in that order.
                let count = (byte1 >> 4) as u8;
                if count > 5 {
                    fail!(BytecodeError::BadArgCount { pos, count })
                }
                let fedc = unit(pos + 2);
                let arg_regs = [
                    u32::from(fedc & 0xf),
                    u32::from((fedc >> 4) & 0xf),
                    u32::from((fedc >> 8) & 0xf),
                    u32::from((fedc >> 12) & 0xf),
                    byte1 & 0xf,
                ];
                for &reg in &arg_regs[..count as usize] {
                    note(reg, 0);
                }
                outs = outs.max(u32::from(count));
            }
            Operands::Args3rc => {
                // [AA|op] [BBBB] [CCCC]: AA registers starting at CCCC.
                let count = byte1;
                let first = u32::from(unit(pos + 2));
                if count > 0 {
                    let last = first + count - 1;
                    if last > u32::from(u16::MAX) {
                        fail!(BytecodeError::RegisterOverflow { pos })
                    }
                    note(last, 0);
                }
                outs = outs.max(count);
            }
        }

        pos += width;
    }

    if max_reg > u32::from(u16::MAX) {
        fail!(BytecodeError::RegisterOverflow { pos })
    }

    Ok(InsnScan {
        registers_used: max_reg as u16,
        outs_size: outs.min(u32::from(u16::MAX)) as u16,
        units_walked: pos,
    })
}

/// Width in code units of the payload starting at `pos`, whose first unit is
/// `ident`.
fn payload_units(
    insns: &[u8],
    units: usize,
    pos: usize,
    ident: u16,
) -> Result<usize, BytecodeError> {
    let unit = |i: usize| -> Result<u32, BytecodeError> {
        if i >= units {
            return Err(BytecodeError::Truncated { pos });
        }
        Ok(u32::from(u16::from_le_bytes([
            insns[i * 2],
            insns[i * 2 + 1],
        ])))
    };

    let width = match ident {
        // packed-switch-payload: size u16, first_key u32, targets[size] u32.
        0x0100 => unit(pos + 1)? * 2 + 4,
        // sparse-switch-payload: size u16, keys[size] u32, targets[size] u32.
        0x0200 => unit(pos + 1)? * 4 + 2,
        // fill-array-data-payload: element_width u16, size u32, data[].
        0x0300 => {
            let element_width = unit(pos + 1)?;
            let size = unit(pos + 2)? | (unit(pos + 3)? << 16);
            let data_units = (u64::from(size) * u64::from(element_width)).div_ceil(2);
            u32::try_from(data_units + 4).map_err(|_| BytecodeError::Truncated { pos })?
        }
        _ => return Err(BytecodeError::UnknownPayload { ident, pos }),
    } as usize;

    if units - pos < width {
        return Err(BytecodeError::Truncated { pos });
    }
    Ok(width)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble code units into the little-endian byte stream `scan_insns` takes.
    fn insns(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn walks_a_narrow_method() {
        // const/4 v1, #0 ; return-void
        let code = insns(&[0x0112, 0x000e]);
        let scan = scan_insns(&code).unwrap();
        assert_eq!(scan.registers_used, 2);
        assert_eq!(scan.outs_size, 0);
        assert_eq!(scan.units_walked, 2);
    }

    #[test]
    fn counts_the_high_half_of_a_wide_operand() {
        // return-wide v14 must reserve v15 as well.
        let code = insns(&[0x0e10]);
        assert_eq!(scan_insns(&code).unwrap().registers_used, 16);

        // return v14 is narrow, so v15 stays untouched.
        let narrow = insns(&[0x0e0f]);
        assert_eq!(scan_insns(&narrow).unwrap().registers_used, 15);
    }

    #[test]
    fn shift_long_leaves_the_distance_register_narrow() {
        // shl-long v0, v2, v9: vA and vB are pairs, vC is a plain int.
        let code = insns(&[0x00a3, 0x0902]);
        let scan = scan_insns(&code).unwrap();
        // vB=v2 spans v2/v3, vC=v9 is narrow, so the top register is v9.
        assert_eq!(scan.registers_used, 10);
    }

    #[test]
    fn tracks_invoke_argument_windows() {
        // invoke-virtual {v1, v2, v3}, method@0 -> 3 outgoing words.
        let code = insns(&[0x306e, 0x0000, 0x0321]);
        let scan = scan_insns(&code).unwrap();
        assert_eq!(scan.outs_size, 3);
        assert_eq!(scan.registers_used, 4);
    }

    #[test]
    fn tracks_range_invoke_argument_windows() {
        // invoke-virtual/range {v3 .. v7}, method@0 -> 5 outgoing words.
        let code = insns(&[0x0574, 0x0000, 0x0003]);
        let scan = scan_insns(&code).unwrap();
        assert_eq!(scan.outs_size, 5);
        assert_eq!(scan.registers_used, 8);
    }

    #[test]
    fn steps_over_a_packed_switch_payload() {
        // packed-switch v0, +3 ; goto +0 ; <payload: 2 targets> ; return-void
        let code = insns(&[
            0x002b, 0x0003, 0x0000, // packed-switch v0, +3
            0x0028, // goto +0
            0x0100, 0x0002, 0x0000, 0x0000, // ident, size=2, first_key=0
            0x0000, 0x0000, 0x0000, 0x0000, // two u32 targets
            0x000e, // return-void
        ]);
        let scan = scan_insns(&code).unwrap();
        assert_eq!(scan.units_walked, code.len() / 2);
        assert_eq!(scan.registers_used, 1);
    }

    #[test]
    fn steps_over_a_fill_array_data_payload() {
        // fill-array-data v0, +3 ; goto +0 ; <payload: 4 bytes of data>
        let code = insns(&[
            0x0026, 0x0003, 0x0000, // fill-array-data v0, +3
            0x0028, // goto +0
            0x0300, 0x0001, 0x0004, 0x0000, // ident, element_width=1, size=4
            0x0201, 0x0403, // four bytes of data
        ]);
        let scan = scan_insns(&code).unwrap();
        assert_eq!(scan.units_walked, code.len() / 2);
    }

    #[test]
    fn rejects_an_unused_opcode() {
        let code = insns(&[0x000e, 0x0073]);
        let err = scan_insns(&code).unwrap_err();
        assert_eq!(err.error, BytecodeError::UnknownOpcode { op: 0x73, pos: 1 });
        // The clean prefix is still reported so callers can fall back to it.
        assert_eq!(err.scan.units_walked, 1);
    }

    #[test]
    fn rejects_an_instruction_cut_off_at_the_end() {
        // const-string v0 needs two units but only one is present.
        let code = insns(&[0x001a]);
        let err = scan_insns(&code).unwrap_err();
        assert_eq!(err.error, BytecodeError::Truncated { pos: 0 });
    }

    #[test]
    fn rejects_an_odd_byte_count() {
        let err = scan_insns(&[0x0e]).unwrap_err();
        assert_eq!(err.error, BytecodeError::OddLength(1));
    }

    #[test]
    fn every_defined_opcode_has_a_width() {
        // The unused ranges the DEX spec reserves; everything else must decode.
        let unused = |op: u8| {
            matches!(op, 0x3e..=0x43)
                || op == 0x73
                || matches!(op, 0x79..=0x7a)
                || matches!(op, 0xe3..=0xf9)
        };
        for op in 0u8..=0xff {
            assert_eq!(
                format_of(op).is_none(),
                unused(op),
                "opcode 0x{op:02x} disagrees with the unused-range table"
            );
        }
    }
}
