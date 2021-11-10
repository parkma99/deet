use std::collections::HashMap;

use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::Inferior;
use rustyline::error::ReadlineError;
use rustyline::Editor;
pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    breakpoints: HashMap<usize, u8>,
}

fn parse_address(addr: &str) -> Option<usize> {
    let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    usize::from_str_radix(addr_without_0x, 16).ok()
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
            }
        };
        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);
        let breakpoints = HashMap::new();
        debug_data.print();
        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data: debug_data,
            breakpoints:breakpoints,
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if self.inferior.is_some() {
                        println!("some process running");
                    } else {
                        if let Some(inferior) = Inferior::new(&self.target, &args, &mut self.breakpoints)
                        {
                            self.inferior = Some(inferior);
                            match self
                                .inferior
                                .as_mut()
                                .unwrap()
                                .continue_run(&self.breakpoints)
                                .expect("error")
                            {
                                crate::inferior::Status::Stopped(_sig, _rip) => {
                                    println!("Child stopped by signal ({})", _sig,);
                                    let line = self.debug_data.get_line_from_addr(_rip);
                                    let fun = self.debug_data.get_function_from_addr(_rip);
                                    if line.is_some() {
                                        println!("Stopped at {} ({})", fun.unwrap(), line.unwrap());
                                    }
                                }
                                crate::inferior::Status::Exited(_code) => {
                                    println!("Child exited (status {})", _code);
                                    self.inferior = None;
                                }
                                crate::inferior::Status::Signaled(_sig) => {
                                    println!("Child exited due to signal ({})", _sig);
                                    self.inferior = None;
                                }
                            }
                        } else {
                            println!("Error starting subprocess");
                        }
                    }
                }
                DebuggerCommand::Quit => {
                    if self.inferior.is_none() {
                        return;
                    } else {
                        let pid = self
                            .inferior
                            .as_mut()
                            .unwrap()
                            .kill()
                            .expect("error when kill process");
                        println!("Killing running inferior (pid {})", pid);
                        return;
                    }
                }
                DebuggerCommand::Continue => {
                    if self.inferior.is_none() {
                        println!("nothing is running")
                    } else {
                        match self
                            .inferior
                            .as_mut()
                            .unwrap()
                            .continue_run(&self.breakpoints)
                            .expect("error")
                        {
                            crate::inferior::Status::Stopped(_sig, _rip) => {
                                println!("Child stopped by signal ({})", _sig);
                                let line = self.debug_data.get_line_from_addr(_rip);
                                let fun = self.debug_data.get_function_from_addr(_rip);
                                if line.is_some() {
                                    println!("Stopped at {} ({})", fun.unwrap(), line.unwrap());
                                }
                            }
                            crate::inferior::Status::Exited(_code) => {
                                println!("Child exited (status {})", _code);
                                self.inferior = None;
                            }
                            crate::inferior::Status::Signaled(_sig) => {
                                println!("Child exited due to signal ({})", _sig);
                                self.inferior = None;
                            }
                        }
                    }
                }
                DebuggerCommand::Backtrace => {
                    if self.inferior.is_none() {
                        println!("nothing is runing!");
                    } else {
                        self.inferior
                            .as_mut()
                            .unwrap()
                            .print_backtrace(&self.debug_data)
                            .expect("ssss");
                    }
                }
                DebuggerCommand::Break(args) => {
                    let addr: Option<usize> = if args.starts_with("*") {
                        let _addr = parse_address(&args[1..]);
                        match _addr {
                            Some(_a) => Some(_a),
                            None => None,
                        }
                    } else {
                        let line =  usize::from_str_radix(&args, 10);
                        match line {
                            Ok(_line) => {println!("{:?}",self.debug_data.get_addr_for_line(None,_line)); self.debug_data.get_addr_for_line(None,_line)}
                            Err(_) => {println!("{:?}",self.debug_data.get_addr_for_function(None,&args)); self.debug_data.get_addr_for_function(None,&args)}
                        }
                    };
                    match addr {
                        Some(_addr) => {
                            if self.inferior.is_none(){
                                println!("Set breakpoint {} at {:#x}", self.breakpoints.len(), _addr);
                                self.breakpoints.insert(_addr, 0);
                            }else {
                                match self.inferior.as_mut().unwrap().write_byte(_addr, 0xcc).ok() {
                                    Some(_ori) => {
                                        self.breakpoints.insert(_addr, _ori);
                                        println!("Set breakpoint {} at {:#x}", self.breakpoints.len(), _addr);
                                    }
                                    None => println!("Invalid address"),
                                }
                            }
                        }
                        None => println!("wrong address!"),
                    }
                }
            }
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
