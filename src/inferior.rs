use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::process::Child;
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::mem::size_of;

use crate::dwarf_data::DwarfData;
pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}
fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(size_of::<usize>() as isize) as usize)
}

pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>,breakpoint:&mut HashMap<usize, u8>) -> Option<Inferior> {
       let mut cmd = Command::new(target);
       cmd.args(args);
        unsafe {
            cmd.pre_exec(child_traceme);
        }
        let child = cmd.spawn().expect("error when create child process");
        let mut inferior = Inferior {child : child};
        let bpc = breakpoint.clone();
        for (addr,_) in bpc{
            if let Ok(_orig) = inferior.write_byte(addr,0xcc) {
                breakpoint.insert(addr,_orig);
            } else {
                println!("Invalid breakpoint address {:#x}",addr);
            }
        }
        match inferior.wait(None).ok()?{
            Status::Stopped(sig, _) => {
                if sig==signal::Signal::SIGTRAP{
                    return Some(inferior);
                }else {
                    return None;
                }
            }
            Status::Exited(_) => return None,
            Status::Signaled(_) => return None,
        } 
    }
    pub fn continue_run(&mut self,breakpoint:&HashMap<usize, u8>) -> Result<Status,nix::Error>{
        let mut regs = ptrace::getregs(self.pid())?;        
        let rip = regs.rip as usize;
        if let Some(orig) = breakpoint.get(&(rip - 1)){
            self.write_byte(rip - 1, *orig).unwrap();
            regs.rip = (rip - 1) as u64;
            ptrace::setregs(self.pid(), regs).unwrap();
            ptrace::step(self.pid(), None).unwrap();
            match self.wait(None).unwrap() {
                Status::Exited(exit_code) => return Ok(Status::Exited(exit_code)), 
                Status::Signaled(signal) => return Ok(Status::Signaled(signal)),
                Status::Stopped(_, _) => {
                    self.write_byte(rip - 1, 0xcc).unwrap();
                }
            }
        }
        ptrace::cont(self.pid(),None)?;
        self.wait(None)
    }
    pub fn kill(&mut self) ->Result<Pid,std::io::Error>{
        let pid = self.pid();
        match self.child.kill(){
            Ok(_) => {
                return Ok(pid);
            }
            Err(_err) => Err(_err),
        } 
    }
    pub fn print_backtrace(&self,debug_data: &DwarfData) -> Result<(), nix::Error>{
        let pid = self.pid();
        let regs = ptrace::getregs(pid).expect("erro when get regs");
        let mut rip = regs.rip as usize;
        let mut rbp = regs.rbp as usize;
        loop {
            let fun = debug_data.get_function_from_addr(rip);
            let line = debug_data.get_line_from_addr(rip);
            match (&fun,&line) {
                (None, None) => println!("unknown function unknown file"),
                (None, Some(_line)) =>println!("unknown function ({})",_line),
                (Some(_fun), None) =>println!("{},unknown file",_fun),
                (Some(_fun), Some(_line)) => println!("{} ({})",_fun,_line),
            }
            match &fun {
                Some(_fun) => {
                    if _fun == "main"{
                        break;
                    }
                }
                None => break,
            }
            rip = ptrace::read(self.pid(), (rbp+8) as ptrace::AddressType)? as usize;
            rbp = ptrace::read(self.pid(), rbp as ptrace::AddressType)? as usize;
        }
        Ok(())
    } 
    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    pub fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }
}
