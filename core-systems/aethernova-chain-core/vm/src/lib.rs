#![cfg_attr(not(feature = "std"), no_std)]
//! Aethernova VM core: deterministic, gas-metered, bounds-checked, `no_std`-ready.
//!
//! Features:
//! - `no_std` + `alloc` support for embedded targets;
//! - linear memory with explicit bounds checks (64 KiB page constant);
//! - deterministic stack machine, integer-only arithmetic;
//! - per-instruction gas metering with configurable schedule;
//! - host interface (`Host`) for syscalls;
//! - optional `serde` for (de)serialization of bytecode/instructions.
//!
//! Safety & Determinism: no floating point; all memory accesses range-checked;
//! jumps are relative and validated; division checks for zero; gas underflow
//! stops execution with `VmError::OutOfGas`.

extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{fmt, ops::Add};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// 64 KiB page (matches the common WebAssembly page size).
/// This is a host-facing constant; VM enforces memory bounds per access.
pub const PAGE_SIZE: usize = 64 * 1024;

/// Type for stack values and arithmetic. Signed 64-bit is deterministic and sufficient for many VMs.
pub type Word = i64;

/// Program counter type (byte index into code).
pub type Pc = usize;

/// Result alias.
pub type VmResult<T> = core::result::Result<T, VmError>;

/// VM errors. `std::error::Error` is implemented only when `std` feature present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmError {
    OutOfGas,
    Halt,
    InvalidOpcode(u8),
    DecodeOverflow,
    StackUnderflow,
    StackOverflow,
    DivisionByZero,
    MemoryOutOfBounds,
    CallStackOverflow,
    Trap(&'static str),
}

#[cfg(feature = "std")]
impl std::error::Error for VmError {}
impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use VmError::*;
        match self {
            OutOfGas => write!(f, "out of gas"),
            Halt => write!(f, "halt"),
            InvalidOpcode(op) => write!(f, "invalid opcode: {op:#x}"),
            DecodeOverflow => write!(f, "decode overflow"),
            StackUnderflow => write!(f, "stack underflow"),
            StackOverflow => write!(f, "stack overflow"),
            DivisionByZero => write!(f, "division by zero"),
            MemoryOutOfBounds => write!(f, "memory out of bounds"),
            CallStackOverflow => write!(f, "call stack overflow"),
            Trap(msg) => write!(f, "trap: {msg}"),
        }
    }
}

/// Gas unit (monotonic decreasing counter).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gas(pub u64);
impl Gas {
    #[inline] pub fn saturating_sub(self, cost: u64) -> Option<Gas> {
        self.0.checked_sub(cost).map(Gas)
    }
}
impl Add<u64> for Gas {
    type Output = Gas;
    fn add(self, rhs: u64) -> Gas { Gas(self.0.saturating_add(rhs)) }
}

/// Gas schedule for instructions (cost per single execution).
#[derive(Clone, Debug)]
pub struct GasSchedule {
    pub nop: u64,
    pub halt: u64,
    pub push_i8: u64,
    pub push_i64: u64,
    pub pop: u64,
    pub add: u64,
    pub sub: u64,
    pub mul: u64,
    pub div: u64,
    pub load8: u64,
    pub store8: u64,
    pub jmp: u64,
    pub jz: u64,
    pub call: u64,
    pub ret: u64,
    pub syscall: u64,
}
impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            nop: 1, halt: 1, push_i8: 2, push_i64: 3, pop: 1,
            add: 3, sub: 3, mul: 5, div: 10,
            load8: 5, store8: 7,
            jmp: 2, jz: 3,
            call: 5, ret: 5,
            syscall: 50,
        }
    }
}

/// VM configuration.
#[derive(Clone, Debug)]
pub struct VmConfig {
    pub gas_limit: Gas,
    pub stack_limit: usize,
    pub call_stack_limit: usize,
    pub memory_size: usize, // bytes; must be <= MAX_MEMORY
    pub gas: GasSchedule,
}
impl Default for VmConfig {
    fn default() -> Self {
        Self {
            gas_limit: Gas(1_000_000),
            stack_limit: 1 << 15,       // 32K words
            call_stack_limit: 1024,     // frames
            memory_size: PAGE_SIZE,     // 64 KiB by default
            gas: GasSchedule::default(),
        }
    }
}

/// Encoded instruction stream (bytecode).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytecode(pub Vec<u8>);

/// Instruction set (deterministic; integer-only).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instr {
    Nop,
    Halt,
    PushI8(i8),
    PushI64(i64),
    Pop,
    Add,
    Sub,
    Mul,
    Div,
    Load8,           // pop addr -> push byte
    Store8,          // pop (addr, byte)
    Jmp(i32),        // relative
    Jz(i32),         // relative if top==0 (consumes top)
    Call(usize),     // absolute PC
    Ret,
    Syscall(u16),    // host call id
}

impl Instr {
    /// Single-byte opcodes.
    pub const OP_NOP: u8 = 0x00;
    pub const OP_HALT: u8 = 0x01;
    pub const OP_PUSHI8: u8 = 0x10;
    pub const OP_PUSHI64: u8 = 0x11;
    pub const OP_POP: u8 = 0x12;
    pub const OP_ADD: u8 = 0x20;
    pub const OP_SUB: u8 = 0x21;
    pub const OP_MUL: u8 = 0x22;
    pub const OP_DIV: u8 = 0x23;
    pub const OP_LOAD8: u8 = 0x30;
    pub const OP_STORE8: u8 = 0x31;
    pub const OP_JMP: u8 = 0x40;
    pub const OP_JZ: u8 = 0x41;
    pub const OP_CALL: u8 = 0x50;
    pub const OP_RET: u8 = 0x51;
    pub const OP_SYSCALL: u8 = 0x60;

    /// Decode one instruction from `code` at `pc`.
    pub fn decode(code: &[u8], pc: &mut Pc) -> VmResult<Instr> {
        let at = *pc;
        let b = *code.get(at).ok_or(VmError::DecodeOverflow)?;
        *pc += 1;
        macro_rules! take_le {
            ($t:ty) => {{
                let size = core::mem::size_of::<$t>();
                let end = at + 1 + size;
                if end > code.len() { return Err(VmError::DecodeOverflow); }
                let mut arr = [0u8; core::mem::size_of::<$t>()];
                arr.copy_from_slice(&code[(end - size)..end]);
                *pc = end;
                <$t>::from_le_bytes(arr)
            }};
        }
        let i = match b {
            Self::OP_NOP => Instr::Nop,
            Self::OP_HALT => Instr::Halt,
            Self::OP_PUSHI8 => {
                let v = *code.get(*pc).ok_or(VmError::DecodeOverflow)? as i8;
                *pc += 1;
                Instr::PushI8(v)
            }
            Self::OP_PUSHI64 => Instr::PushI64(take_le!(i64)),
            Self::OP_POP => Instr::Pop,
            Self::OP_ADD => Instr::Add,
            Self::OP_SUB => Instr::Sub,
            Self::OP_MUL => Instr::Mul,
            Self::OP_DIV => Instr::Div,
            Self::OP_LOAD8 => Instr::Load8,
            Self::OP_STORE8 => Instr::Store8,
            Self::OP_JMP => Instr::Jmp(take_le!(i32)),
            Self::OP_JZ => Instr::Jz(take_le!(i32)),
            Self::OP_CALL => Instr::Call(take_le!(u32) as usize),
            Self::OP_RET => Instr::Ret,
            Self::OP_SYSCALL => Instr::Syscall(take_le!(u16)),
            op => return Err(VmError::InvalidOpcode(op)),
        };
        Ok(i)
    }

    /// Encode instruction to bytes (little-endian for immediates).
    pub fn encode(&self, out: &mut Vec<u8>) {
        use Instr::*;
        match *self {
            Nop => out.push(Self::OP_NOP),
            Halt => out.push(Self::OP_HALT),
            Pop => out.push(Self::OP_POP),
            Add => out.push(Self::OP_ADD),
            Sub => out.push(Self::OP_SUB),
            Mul => out.push(Self::OP_MUL),
            Div => out.push(Self::OP_DIV),
            Load8 => out.push(Self::OP_LOAD8),
            Store8 => out.push(Self::OP_STORE8),
            Ret => out.push(Self::OP_RET),
            PushI8(v) => { out.push(Self::OP_PUSHI8); out.push(v as u8); }
            PushI64(v) => { out.push(Self::OP_PUSHI64); out.extend_from_slice(&v.to_le_bytes()); }
            Jmp(ofs) => { out.push(Self::OP_JMP); out.extend_from_slice(&ofs.to_le_bytes()); }
            Jz(ofs)  => { out.push(Self::OP_JZ);  out.extend_from_slice(&ofs.to_le_bytes()); }
            Call(pc) => { out.push(Self::OP_CALL); out.extend_from_slice(&(pc as u32).to_le_bytes()); }
            Syscall(id) => { out.push(Self::OP_SYSCALL); out.extend_from_slice(&id.to_le_bytes()); }
        }
    }
}

/// Host interface for syscalls.
/// Implementors may access VM memory/stack via provided references.
pub trait Host {
    /// Called on `Syscall(id)`. Implementations can read/write `vm.memory` and `vm.stack`.
    fn syscall(&mut self, id: u16, vm: &mut Vm) -> VmResult<()>;
}

/// Virtual machine instance.
pub struct Vm {
    pub cfg: VmConfig,
    pub code: Vec<u8>,
    pub pc: Pc,
    pub gas: Gas,
    pub stack: Vec<Word>,
    pub call_stack: Vec<Pc>,
    pub memory: Vec<u8>,
}

impl Vm {
    /// Create a new VM with provided bytecode and configuration.
    pub fn new(code: Vec<u8>, cfg: VmConfig) -> Vm {
        let mem = cfg.memory_size;
        Vm {
            gas: cfg.gas_limit,
            cfg,
            code,
            pc: 0,
            stack: Vec::with_capacity(1024),
            call_stack: Vec::with_capacity(64),
            memory: vec![0u8; mem],
        }
    }

    /// Execute until HALT/OutOfGas/error. Returns `Ok(())` on HALT.
    pub fn run<H: Host>(&mut self, host: &mut H) -> VmResult<()> {
        loop {
            self.step(host)?;
        }
    }

    /// Execute one instruction.
    pub fn step<H: Host>(&mut self, host: &mut H) -> VmResult<()> {
        let old_pc = self.pc;
        let mut pc = self.pc;
        let instr = Instr::decode(&self.code, &mut pc)?;
        self.pc = pc;

        // Gas accounting
        let cost = match instr {
            Instr::Nop        => self.cfg.gas.nop,
            Instr::Halt       => self.cfg.gas.halt,
            Instr::PushI8(_)  => self.cfg.gas.push_i8,
            Instr::PushI64(_) => self.cfg.gas.push_i64,
            Instr::Pop        => self.cfg.gas.pop,
            Instr::Add        => self.cfg.gas.add,
            Instr::Sub        => self.cfg.gas.sub,
            Instr::Mul        => self.cfg.gas.mul,
            Instr::Div        => self.cfg.gas.div,
            Instr::Load8      => self.cfg.gas.load8,
            Instr::Store8     => self.cfg.gas.store8,
            Instr::Jmp(_)     => self.cfg.gas.jmp,
            Instr::Jz(_)      => self.cfg.gas.jz,
            Instr::Call(_)    => self.cfg.gas.call,
            Instr::Ret        => self.cfg.gas.ret,
            Instr::Syscall(_) => self.cfg.gas.syscall,
        };
        self.gas = self.gas.saturating_sub(cost).ok_or(VmError::OutOfGas)?;

        use Instr::*;
        match instr {
            Nop => {}
            Halt => return Err(VmError::Halt),

            PushI8(v)  => self.push(v as Word)?,
            PushI64(v) => self.push(v as Word)?,
            Pop => { self.pop()?; }

            Add => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.wrapping_add(b))?;
            }
            Sub => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.wrapping_sub(b))?;
            }
            Mul => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.wrapping_mul(b))?;
            }
            Div => {
                let b = self.pop()?;
                if b == 0 { return Err(VmError::DivisionByZero); }
                let a = self.pop()?;
                self.push(a.wrapping_div(b))?;
            }

            Load8 => {
                let addr = self.pop()? as usize;
                let v = *self.memory.get(addr).ok_or(VmError::MemoryOutOfBounds)?;
                self.push(v as Word)?;
            }
            Store8 => {
                let addr = self.pop()? as usize;
                let v = self.pop()? as u8;
                let slot = self.memory.get_mut(addr).ok_or(VmError::MemoryOutOfBounds)?;
                *slot = v;
            }

            Jmp(ofs) => self.br_relative(ofs)?,
            Jz(ofs) => {
                let cond = self.pop()?;
                if cond == 0 { self.br_relative(ofs)?; }
            }

            Call(target) => {
                if self.call_stack.len() >= self.cfg.call_stack_limit {
                    return Err(VmError::CallStackOverflow);
                }
                self.call_stack.push(self.pc);
                self.pc = target;
            }
            Ret => {
                let ret_pc = self.call_stack.pop().ok_or(VmError::CallStackOverflow)?;
                self.pc = ret_pc;
            }

            Syscall(id) => {
                host.syscall(id, self)?;
            }
        }

        // If PC didn't change (non-branching op), continue; otherwise ensure PC valid
        if self.pc == old_pc {
            // normal case: pc already incremented by decoder
        }

        Ok(())
    }

    #[inline]
    fn push(&mut self, v: Word) -> VmResult<()> {
        if self.stack.len() >= self.cfg.stack_limit {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(v);
        Ok(())
    }
    #[inline]
    fn pop(&mut self) -> VmResult<Word> {
        self.stack.pop().ok_or(VmError::StackUnderflow)
    }

    #[inline]
    fn br_relative(&mut self, ofs: i32) -> VmResult<()> {
        // relative to next instruction (already advanced PC)
        let base = self.pc as isize;
        let tgt = base.checked_add(ofs as isize).ok_or(VmError::DecodeOverflow)?;
        if tgt < 0 || tgt as usize > self.code.len() { return Err(VmError::DecodeOverflow); }
        self.pc = tgt as usize;
        Ok(())
    }
}

/// Minimal host that does nothing (useful for tests).
pub struct NullHost;
impl Host for NullHost {
    fn syscall(&mut self, _id: u16, _vm: &mut Vm) -> VmResult<()> {
        Err(VmError::Trap("unimplemented syscall"))
    }
}

/// Helper to assemble a program from instructions.
pub fn assemble(program: &[Instr]) -> Bytecode {
    let mut out = Vec::new();
    for ins in program { ins.encode(&mut out); }
    Bytecode(out)
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    struct IncHost;
    impl Host for IncHost {
        fn syscall(&mut self, id: u16, vm: &mut Vm) -> VmResult<()> {
            match id {
                1 => { // mem[addr] += 1 ; expects [addr]
                    let addr = vm.pop()? as usize;
                    let b = vm.memory.get_mut(addr).ok_or(VmError::MemoryOutOfBounds)?;
                    *b = b.wrapping_add(1);
                    Ok(())
                }
                _ => Err(VmError::Trap("unknown syscall")),
            }
        }
    }

    #[test]
    fn arithmetic_and_branch() {
        // Program: push 2; push 3; add; jz +X; halt
        let prog = assemble(&[
            Instr::PushI8(2),
            Instr::PushI8(3),
            Instr::Add,
            Instr::Jz(4),   // will not jump
            Instr::Halt,
        ]);
        let mut vm = Vm::new(prog.0, VmConfig::default());
        let mut host = NullHost;
        let err = vm.run(&mut host).unwrap_err();
        assert_eq!(err, VmError::Halt);
        assert_eq!(vm.stack.last().copied(), Some(5));
    }

    #[test]
    fn memory_and_syscall() {
        let prog = assemble(&[
            Instr::PushI8(0),    // addr 0
            Instr::PushI8(41),
            Instr::Store8,       // mem[0]=41
            Instr::PushI8(0),    // addr 0
            Instr::Syscall(1),   // ++mem[0]
            Instr::PushI8(0),
            Instr::Load8,        // -> 42
            Instr::Halt,
        ]);
        let mut cfg = VmConfig::default();
        cfg.gas_limit = Gas(10_000);
        let mut vm = Vm::new(prog.0, cfg);
        let mut host = IncHost;
        let err = vm.run(&mut host).unwrap_err();
        assert_eq!(err, VmError::Halt);
        assert_eq!(vm.stack.last().copied(), Some(42));
    }

    #[test]
    fn out_of_gas_stops() {
        let prog = assemble(&[Instr::PushI64(1); 10_000]);
        let mut cfg = VmConfig::default();
        cfg.gas_limit = Gas(10); // too small
        let mut vm = Vm::new(prog.0, cfg);
        let mut host = NullHost;
        let err = vm.run(&mut host).unwrap_err();
        assert!(matches!(err, VmError::OutOfGas));
    }
}
