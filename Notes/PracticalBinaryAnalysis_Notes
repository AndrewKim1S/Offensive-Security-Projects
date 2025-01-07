
###############################################################################
#                         Practical Binary Analysis                           #
#                         Start Date: June 21, 2024                           #
#                         End Date: July 17, 2024                             #
#                            Status: Complete                                 #
###############################################################################
General:
* Environment: Ubuntu 16, gcc 5.6 
* user: binary, pass: binary

Sections:
1. Anatomy of a Binary
  - C compilation
  - Symbols & Stripped Binaries
  - Disassembling a Binary
  - Loading & Executing a Binary
2. The ELF Format
  - The Executable Header
  - Section Header
  - Sections
  - Program Header
3. The PE Format
4. Building a Binary Loader
5. Basic Binary Analysis in Linux
  - System & Library Calls
  - Examining Instruction-Level Behavior
6. Disassembly and Binary Analysis Fundamentals
7. Simple Code Injection Techniques for ELF
  - LD_PRELOAD
  - Injecting Code Section
  - Calling Injected Code
8. Customizing Disassembly
9. Binary Instrumentation
  - Static Binary Instrumentation
  - Dynamic Binary Instrumentation
10. Principles of Dynamic Taint Analysis

Links To Documentation:
* elf format   https://refspecs.linuxfoundation.org/elf/elf.pdf
* elfinject    https://github.com/krakankrakan/elfinject
* hexedit      https://rigaux.org/hexedit.html
* x86_64 Arch  http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html

############################ Anatomy of a Binary ##############################

# C compilation Process
* Typically 1 source file = 1 assembly file = 1 object file
* Preprocessing Phase
  - Expands any #define and #include directives in the source file (so all that is left 
    is pure C) The headers are included in its entirety with all of its type defs, global 
    vars, and function prototypes "copied" into the source file.
* Compilation Phase
  - Takes the perprocessed code and translates it into assembly 
* Assembly Phase
  - Given the assembly files generated in compilation phase, the output is a set of object 
    files. Object files contain machine instructions 
  - Object file can be relocatable, which don't rely on being placed at a particular addr 
    in memory. Object files are compiled independently from each other, so the assembler 
    has no way of knowing the memory addresses of other obj files. (This is why obj files 
    need to relocatable so they can be linked together in any order to form a complete 
    binary executable)
* Linking Phase
  - (Linker) links together all the object files into a single binary executable
  - Object files may reference functions of variables in other obj files or in libraries 
    that are external to the program. Before the linking phase, the addresses at which the 
    referenced code and data will be placed is not known, so obj files only contain 
    relocation symbols.
    - References that rely on a relocation symbol are called symbolic references
  - Relocation Symbols specify how function and variable references should be resolved
  - Static Libraries 
    - They are merged into the binary executable, allowing any references to them to 
      be resolved entirely
  - Dynamic (shared) Libraries are shared in memory among all programs that run on the
    system.
    - Rather than copying the library into the binary, they are loaded into memory only
      once and any binary that wants to use it must use this shared copy. This addr is 
      not known during Linking so the linker leaves symbolic references to these 
      libraries even in the final exec. They are resolved when the binary is actually 
      loaded into memory.

# Symbols and Stripped Binaries
* When compiling a program, compilers emit symbols which keep track of funcs & vars
  - $readelf --syms a.out
  - Shows dynamic symbols (for resolveing dynamic dependencies) & static symbols
* Stripping a binary removes symbol & other information from a binary
  - $strip --strip-all a.out

# Disassembling a Binary
* We can use the objdump utility to disassemble obj and bin files
  - objdump -sj .rodata compilation_example.o  (show read only data section)
  - objdump -M intel -d compilation_example.o  (disassembles all the code in obj file)
* When disassembling a binary
  - .text section is the main code section & contains main function
  - When binary is stripped functions in .text section are all merged 

# Loading and Executing a Binary
* How a binary is represented in memory (Linux)

  |____________|
  |            |
  |   Kernel   |
  |____________|
  |____________|
  |            |
  |   Stack    |
  |____________|
  |____________|
  |            |
  |   Memory   |  Interpreter 
  |  Mapping   |  lib1.so
  |    Area    |  lib2.so
  |____________|
  |____________|
  |            |
  |    Heap    |
  |____________|
  |____________|  Header
  |            |  Data Section 1
  |    Data    |  Data Section 2
  |____________|
  |            |  Code Section 1
  |    Code    |  Code Section 2
  |____________|
  |            |      Binary
  Virtual Memory

* When starting to run a binary
  - The OS starts by setting a new process for the program to run in, including a va space
  - The OS maps and interpreter (user space program) into the process's virtual mem. 
    - Linux ld-linux.so, Windows ntdll.dll
    - Linux ELF binaries come with a section called .interp that specifies the path to 
    interpreter that will be used to load the binary
  - Interpreter loads binary into its va. Then parses the binary to find what dynamic libs 
    the binary uses. This is then mapped into the va space and performs any nessecary 
    relocations in the binary's code sections to fill in the correct addresses for 
    references to dynamic libs
  - Lazy Binding, is when relocations are not done right away when loaded but deffered
    until the first reference to the unresolved location is made
  - After relocation is complete, the interpreter looks up the entry point of the binary 
    and transfers control to it, beginning normal execution of the binary
    

############################## The ELF Format #################################

* Executable and Linkable Format (ELF) is the default binary format on linux-based systems
  It is used for executable files, object files, chared libraries, and core dumps
* ELF binary components
  1. executable header
  2. program headers (optional)
  3. sections
  4. section headers (optional) one per section
* The program header and section header tables need not be located at any particular offset 
  in the binary file
  
      ___ |_____________________|
     |    |                     |
  Header  |  Executable header  |
     |___ |_____________________|
     |    |                     |
     |    |_____________________|
  Program |                     |
  headers |   Program header    | 
     |    |_____________________|
     |___ |_____________________|
     |    |                     |
     |    |_____________________|
     |    |                     |
  Section |       Section       |
     |    |_____________________|
     |    |                     |
     |___ |_____________________|
     |    |_____________________|
     |    |                     |
  Section |   Section header    |
  headers |_____________________|
     |    |                     |
     |___ |_____________________|
             64-bit ELF binary 

# The Executable Header
  typedef struct {
    unsigned char e_ident[16];   // Magic number (0x7f, E, L, F) and other info
    uint16_t      e_type;        // Object file type
    uint16_t      e_machine;     // Architecture
    uint32_t      e_version;     // Object file version
    uint64_t      e_entry;       // Entry point virtual address
    uint64_t      e_phoff;       // Program header table file offset
    uint64_t      e_shoff;       // Section header table file offset
    uint32_t      e_flags;       // Processor-specific flags
    uint16_t      e_ehsize;      // ELF header size in bytes
    uint16_t      e_phentsize;   // Program header table entry size
    uint16_t      e_phnum;       // Program header table entry count
    uint16_t      e_shentsize;   // Section header table entry size
    uint16_t      e_shnum;       // Section header table entry count
    uint16_t      e_shstrndx;    // Section header string table index
                                 // string table section .shstrtab (ASCII string of names)
  } Elf64_Ehdr;

  e_ident[] Identification Indexes
  Name	        Value   Purpose
  EI_MAG0	0	File identification
  EI_MAG1	1	File identification
  EI_MAG2	2	File identification
  EI_MAG3	3	File identification
  EI_CLASS	4	File class
  EI_DATA	5	Data encoding
  EI_VERSION	6	File version
  EI_OSABI	7	Operating system/ABI identification
  EI_ABIVERSION	8	ABI version
  EI_PAD	9	Start of padding bytes
  EI_NIDENT	16	Size of e_ident[]

* "Every ELF file starts with an executable header which is just a structured series of
  bytes telling you that it's an ELF file, what kind of ELF file, and where to find other 
  contents"
* show ELF header
  - $ readelf -h a.out 

# Section Headers 
* The code and data in an ELF binary are logically divided into contiguous nonoverlapping 
  chunks. These sections do not have any predetermined structure, and varies depending on 
  contents
  - Every Section is described by a section header 
* Becuase sections are intended to provide a view for the linker only, the section header 
  table is optional. ELF files that don't need linking are not required to have a section  
  header table

  typedef struct {
    uint32_t sh_name;       // Section name - index into string table .shrstrtab
    uint32_t sh_type;       // Section type
                            // SHT_PROGBITS contain program data (instr or constants)
                            // SHT_SYMTAB static symtab, SHT_DYNSYM dynamic symtab
                            // SHT_REL, SHT_RELA contain relocation entries (tells linker
                            // about a particular location in binary where a relocation is
                            // needed & which symbol the relocation should be resolved to
    uint64_t sh_flags;      // Section flags
                            // SHF_WWRITE indicates section is writable at runtime
                            // SHF_ALLOC contents of section are to loaded into virtual 
                            // memory when executing the binary
                            // SHF_EXECINSTR the section contains executable instructions
    uint64_t sh_addr;       // Section virtual addr at execution
    uint64_t sh_offset;     // Section file offset
    uint64_t sh_size;       // Section size in bytes
    uint32_t sh_link;       // Link to another section
    uint32_t sh_info;       // Additional section information
    uint64_t sh_addralign;  // Section alignment
    uint64_t sh_entsize;    // Entry size if section holds table
  } Elf64_Shdr;

# Sections
* .init     // Section runs before any other code. Trasnfers control to main entry point
* .fini     // Section which runs after the main program completes
* .text     // Section where the main code of the program resides. 
  - The .text section of a typical binary compiled by gcc contains a number of standard 
    functions that perform initialization and finalization tasks (_start, 
    register_tm_clones, frame_dummy)
  - _start is the entry point of the binary. At the end it calls main
* .bss      // (Block Started by Symbol) holds uninitialized variables
* .data     // Contains default values of initialized variables
* .rodata   // Read Only data holds constant values 

* Lazy Binding utilizes the sections .plt and .got
* Procedure Linkage Table (.plt)
  - .plt is a code section that contains executable code
  - The PLT consists entirely of stubs dedicated to directing calls from the .text 
    section to the appropriate library location

             Code
   ________________________
  |                        |
  |  .plt                  |
  |________________________|        ________________
  |                        |       |                |
  |  <default stub>:       |       |  .got.plt      |
  |    push QWORD PTR []   |       |________________|
  |    jmp  QWORD PTR []   |       |                |
  |                        | ----> |  .got.plt[n]:  |
  |  <puts@plt>:           |       |    <addr>      |
  |    jmp  QWORD PTR []   |       |________________|
  |    push 0x0            |       |                |
  |    jmp <default stub>  |       |________________|
  |________________________|
  |                        |
  |  .text                 |
  |________________________|
  |                        |
  |  <main>:               |
  |    ...                 |
  |    call puts@plt       |
  |________________________|

Disassembly of a .plt section

1️⃣️00000000004003f0 <puts@plt-0x10>:
  4003f0: push QWORD PTR [rip+0x200c12] # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  4003f6: jmp  QWORD PTR [rip+0x200c14] # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  4003fc: nop  DWORD PTR [rax+0x0]
  
2️⃣️0000000000400400 <puts@plt>:
  400400: jmp QWORD PTR [rip+0x200c12] # 601018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400406: push 3️⃣️0x0
  40040b: jmp 4003f0 <_init+0x28>

4️⃣️0000000000400410 <__libc_start_main@plt>:
  400410: jmp QWORD PTR [rip+0x200c0a] # 601020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400416: push 5️⃣️0x1
  40041b: jmp 4003f0 <_init+0x28>

  - 1 is a default stub
  - 2,4 are function stubs, one per library function
  - 3,5 for each consecutive function stub, the value pushed onto the stack is incremented

* Dynamically Resolving a Library Function Using the PLT
  - To call ex. puts function, I make a call to the corresponding PLT stub, puts@plt
  - PLT stub begins with an indirect jump instruction into .got.plt section. Initially, 
    before lazy allocation has happened this address is the next instruction. (push)
  - The push instr pushes an integer (0x0) to the stack. This is an identifier for the PLT
  - The next instr jumps to the default stub shared by all PLT function stubs. It pushes
    another identifier from GOT identifying the executable itself and jumps to dynamic 
    linker
  - Using the identifier pushed by the PLT stubs, the dynamic linker figures that it
    should resolve the addr of puts and should do so on behalf of the main executable 
    loaded into the process
  - The dynamic linker then looks up the addr at which puts function is located and plugs
    the addr of that function into the GOT entry associated with puts@plt
    - Thus the GOT entry no longer points back into the PLT stub, but now points to the 
      actual addr of puts
  - Dynamic linker transfers control to puts

* Global Offset Table (.got)
  - .got.plt is a data section that is writable
  - It exists as an extra layer of security so that executable sections like .plt and .text
    can not be writable. (AVOID WRITABLE CODE SECTIONS)

* .rel.* & .rela.*  // Table of relocation entries
* .dynamic          // Lists dependencies 
* .init_array       // Data section that contains any number of fptrs.
                    // These are called when binary is init, before main is called
* .fini_array       // Data section that contains any number of fptrs.
                    // These are called when binary is ending, destructors
* .shstrtab         // Array of strings that contain names of all sections in binary
* .symtab           // Contains a symbol table which is a table of Elf64_Sym structs
                    // Associates a symbolic name with a piece of code or data 
                    // elsewhere in the binary such as function or var.
* .strtab           // Strings containing the symbolic names. 
* .dynsym & .dynstr // Analoguous to .symtab & .strtab, except they contain symbols and 
                    // strings needed for dynamic linking
* Disassemble a specific section
  - $ objdump -M intel --section .plt -d a.out

# Program Headers
* Provides a segment view of binary instead of section view.
  - Section view of an ELF binary is meant for static linking purposes
  - Segment view is used for OS during execution and dynamic linker
* An ELF segment encompasses zero or more sections, essentially bundling these into a 
  single chunk
* Because segments provide an execution view they are needed only for executable ELF files
  
  typedef struct {
    uint32_t        p_type;    // Segment type
    uint32_t        p_flags;   // Segment flags
    uint64_t        p_offset;  // Segment file offset
    uint64_t        p_vaddr;   // Segment virtual addr
    uint64_t        p_paddr;   // Segment physical addr
    uint64_t        p_filesz;  // Segment size in file
    uint64_t        p_memsz;   // Segment size in memory
    uint64_t        p_align;   // Segment alignment
  } Elf64_Phdr;

* Read Program headers
  - $ readelf --wide --segments a.out

############################## PE Format ######################################


#################### Building a Binary Loader Using LIBBFD ####################
* The Binary File Descriptor Library (libbfd) provides common interface for reading
  and parsing all popular binary formats
* Static Symbol Table
  - Created at compile time
  - Not needed for process creation
  - Can be stripped from a binary
* Dynamic Symbol Table
  - Created at runtime 
  - Used by dynamic linker to resolve which dynamic libraries to map into the addr space
    of the program

###################### Basic Binary Analysis in Linux #########################
* file
  - finds what type each file is. Not fooled by extensions
  - $ file -z (peek inside zipped files) file
* head
  - outputs first few (10) lines of a file
* tail
  - outputs last few lines of a file
* base64
  - encode binary data as ASCII text
  - $ base64 -d file
* tar xzvf (unzip using gzip and extract payload) payload
  - decompress files
* ldd 
  - find out the shared objects (libraries) required by a program
* xxd
  - outputs the contents of a file in hex
* dd
  - convert or copy a file
  - $ dd skip=52 count=64 if=67b8601 of=elf_header bs=1
* readelf
  - display information about ELF files
* nm
  - display symbol information in object files (can also demangle)
* strings
  - checks for strings in any file (including bins)
  - doesn't check if strings were intended to be readable, so may output bogus results
    as a result of binary sequences that so happen to be printable

* When functions are be overloaded like (C++), compilers emit mangled function names
  A mangled name is a combination of the original function name andd en encoding of the
  function parameters. 
  - Mangled function names give free type information by revealing the expected parameters
    of a function.
* Linker checks the following folders when resolving binary dependencies
  - LD_LIBRARY_PATH environment variable
  - Dirs in binary's rpath
  - For system dirs, /lib, /usr/lib, /lib64, /usr/lib64
  - Dirs specified in /etc/ld.so.conf
* $ echo $? 
  - $? is a special variables in the shell that holds the exit status of the most
    recently executed cmd. 0 indicates success, any non-zero indicates error
* hexedit to modify contents of a binary in hexadecimal 

# Tracing System Calls and Library Calls
* strace
  - show system calls 
* ltrace 
  - show library calls 

# Examining Instruction-Level Behavior
* objdump
  - Examine instruction level assembly code of ELF
* %rdi is a register for the first function argument
  - %rsi (2nd), %rdx (3rd), %rcx (4th), %r8 (5th), %r9 (6th)
* %pc is the program counter
* %rip is instruction pointer. Holds the next instr to be executed
  
################ Disassembly and Binary Analysis Fundamentals #################
* Static Disassembly is where the binary is not executed

# Linear Disassembly - Static 
* Iterates through all code segments in a binary decoding all bytes consecutively and
  parsing them into a list of instructions 
* Problems
  - Not all bytes may be instructions (inline data). Disassembling this may result in 
    invalid opcodes or result in bogus instructions 
  - ISAs with variable length opcodes such as x86, inline data may cause the disassembler
    to become desynchronized with respect to the true instr stream

# Recursive Disassembly - Static
* Sensitive to control flow
* Starts from known entry points into the binary (main entry point, exported function 
  symbols) and recursively follows control flow (jumps, calls) to discover code
* Problems
  - Difficult/Impossible to statically figure out the possible targets of indirect jump
    or calls. Can miss blocks of code or even entire functions

# Dynamic Disassembly
* log instructions while being executing
* Problems
  - code coverage, the analysis only ever sees the instructions that are actually 
    executed during the analysis 
* Test Suites
  - Run the analyzed binary with known test inputs (ex. Makefile tests)
* Fuzzing
  - automatically generate inputs to cover new code paths in a binary

# Structuring Disassembled Code and Data
* Function Detection
  - Unstripped
    - symbol table specifies set of functions (unstripped bins)
  - Stripped 
    - locate functions that are directly addressed by a call instruction (easy)
    - indirect (fptrs), tail called (func ends with call to another func) locate funcs
      using function signature patterns (function prologues, epilogues)

################# Simple Code Injection Techniques for ELF ####################

# Modifying Shared Library Behavior Using LD_PRELOAD
* LD_PRELOAD is env var that specifies libraries for the linker to load before any other
  library. If a preloaded library contains a function with the same name as a function
  in a library loaded later the first function is the one that will be used at runtime
  - Can override library functions even stl lib funcs
  - #include <dlfcn.h> is dynamic linker lib.
    
# Injecting a Code Section
* To add a new section to an ELF binary, first inject the bytes that the section will 
  contain by appending them to the end of the binary. Create a section header and a 
  program header for the injected section.
  - program header table is usually located right after the executable header. Because
    of this adding an extra program header would shift all of the sections and headers
    that come after it. To avoid complex shifting, overwrite an existing program header.
   _____________________
  |                     |  ehdr:
  |  Executable header  |  e_entry  = addr(.text)+off       -> addr(.injected)+off
  |_____________________|
  |                     |
  |_____________________|  phdr:
  |                     |  p_type   = PT_NOTE               -> PT_LOAD
  |   Program header    |  p_offset = off(.note.ABI-tag)    -> off(.injected) 
  |_____________________|  p_flags  = PF_R                  -> PF_R | PF_X
  |_____________________|
  |                     |
  |_____________________|
  |                     |
  |        .text        |
  |_____________________|
  |                     |
  |_____________________|
  |                     |
  |    .not.ABI-tag     |
  |_____________________|
  |_____________________|  shdr:
  |                     |  sh_type   = SHT_NOTE            -> SHT_PROGBITS
  |   Section header    |  sh_addr   = addr(.note.ABI-tag) -> addr(.injected)
  |_____________________|  sh_flags  = SHF_ALLOC           -> SHF_ALLOC | SHF_EXECINSTR
  |_____________________|  sh_addralign = 4                -> 16
  |                     |  sh_size   = size(.note.ABI-tag) -> size(.injected)
  |     .injected       |
  |_____________________|
* Replacing .note.ABI-tag with injected code section

* Program headers which can be safely overwritten is the PT_NOTE header which describes
  PT_NOTE segment
  - The PT_NOTE segment encompasses sections that contain auxiliary info about the binary
  - If a PT_NOTE segment sections are missing, the loader simple assumes it is a native
    binary. 
* Modify the Note program header and section header with new injected section info
  - Optionally modify string table to change the name from .note.ABI-tag -> .injected
- $ ./elfinject ls hello.bin ".injected" 0x800000 0
  - (host_binary) (inject_file) (name) (address_injected_section) (offset_entry_point) 
    -1 if none

* Assembly source code, (.s files) to raw binary file with only binary encodings
  of assembly instructions and data (suitable for injection)
  - $ nasm -f bin -o hello.bin hello.s    
* Must transfer control back to a specific hard coded addr (Calling Injected Code)
  or simply return (Hijacking GOT Entries)

# Calling Injected Code
* Entry Point Modification
  - Can change the entry point in ehdr to the start of the injected section
* Hijacking Constructors and Destructors
  - Overwrite pointers in .init_array or .fini_array which contain pointers to 
    constructors and destructors. injected code can run before or after main 
    
# Hijacking GOT Entries
* Replace an existing library function with injected code
* Overwrite the .got with the address of our injected code. This will mean
  that when the overwritten .plt section jmps to .got table, instead of going to next
  instr (on 1st use) or correct library, it will jmp to injected code.

# Hijacking PLT Entries
* Replace an existing library function with injected code
* Overwrite the indirect jmp instruction to the .got to directly jmp to injected code

# Redirecting Direct and Indirect Calls
* When I want to use an injected function to replace a nonlibrary function, must overwrite
  the calls directly with calls to the injected function

########################### Customizing Disassembly ###########################

# Obfuscation
* Instruction Overlapping
  - Most disassemblers output a single disassembly listing per binary because assumes
    each byte in a binary is mapped to at most one instruction, each instruction is 
    contained in a single basic block, and each block is part of a single func.
    (Assumes that chunks of code don't overlap with each other)
  - x86 instr vary in length, so instr can overlap

# Capstone API to write custom disassemblers
* csh                Capstone handle
* cs_insn            Capstone Instruction
* cs_open()          Open a properly configured Capstone instance
* cs_disasm()        Disassembles a given buffer of machine code. Returns array of instrs  
* cs_close()         Close Capstone instance
* cs_disasm_itera()  Disassembles instrs one by one

# Return Oriented Programming
* Security measure (DEP) Data Execution Prevention, enforces that no region of memory is 
  every writable and executable at the same time.
  - Prevents Stack Smashing attacks
  - Can be circumvented by redirecting existing code in the exploited binary or the libs
    it uses. (ret2libc) 
* Return Oriented Programming 
  - Allows implementation of arbitrary malicious functionality by chaining together short
    existing code sequences (gadgets) in the target program's memory space.
  - Each gadget ends in a return instr and performs a basic operation. By carefully
    selecting gadgets, attacker can create an instr set where each gadget forms an instr
    and then use this instr set to craft arbitrary functionality (ROP program).
  - ROP progrom have series of gadgets where the return instr terminating each gadget
    transfers control to the next gadget in the chain
       _______________
       |              |                     An example ROP chain. Gadget g1 loads
       |     &gn      |                     a constant into eax, which is then added
       |______________|                     to esi by g2
       _______________
       |              |   add esi, eax
       |     &g2      |-> ret
       |______________|
       |              |
       |   constant   |
       |______________|
       |              |   pop eax
       |     &g1      |-> ret
 esp-> |______________|

* Finding ROP Gadgets
  - Find gadgets that end in return instr. Look for both aligned and unaligned gadgets
    Keep gadget length limited
  - To find gadgets scan binary for return instr (aligned & unaligned) and then traverse
    backwards building longer gadgets as you go. 

########################### Binary Instrumentation ############################

* Binary Instrumentation 
  - Inserting new code at any point in an existing binary to observe or modify behavior.
    point where you add new code is (instrumentation point)
    added code (instrumentation code)
* Static (SBI) vs Dynamic Binary Instrumentation (DBI)
  - SBI uses binary rewriting techniques to permanently modify binaries on disk
  - DBI monitors binaries as they execute and inserts new instr into the instr stream 
    on the fly
    
      DBI                                  SBI
    - slow                                 + fast
    - depends on lib & tool                + stand-alone binary
    + Transparently instruments libs       - Must explicitly instrument libraries 
    + Handles dynamically gen code         - Dynamically gen code unsupported
    + Can dynamically attach/detach        - Instruments entire execution
    + No need for disassembly              - Prone to disassembly errors
    + Transparent, no need to modify bin   - Error-prone binary rewriting
    + No symbols needed                    - Symbols preffered to minimize errors

# Static Binary Instrumentation (SBI)

* int 3
  - software interrupt that user-space programs like SBI libraries or debuggers can catch
    in form of a SIGTRAP signal delivered by the OS.
  - instr is 1 byte long (no worry about instr overwriting)
  - Doesn't work for programs that are already being debugged, as int3 for breakpoints
* Trampoline Approach
  - Copies all of the original code and instruments this copied code
  - Uses jmp instrs (trampolines) to redirect the original code to the instrumented copy
   ___________________
  |                   |
  | Executable header |
  |___________________|
  |                   |
  |  Program headers  |
  |___________________|
  |       .text       |
  | <f1>:             |
1️⃣️|   jmp f1_copy     |
2️⃣️|   ; junk bytes    |
  | <f2>:             |
  |   jmp f2_copy     |
  |___________________|
  |                   |
  |       .data       |
  |___________________|
  |   .text.instrum   |
  | <f1_copy>:        |
3️⃣️|   ; nop bytes     |
  |   test edi, edi   |
4️⃣️|   jne _ret        |
  |   ; nop bytes     |
  |   xor eax, eax    |     __________________
5️⃣️|   call f2_copy    |    |<hook_ret>:       |
  | _ret:             |    |  ; save state    | 7️⃣️
6️⃣️|   call hook_ret  --->  |  ...             |
  |   ret             |    |  ; restore state | 8️⃣️
  |                   |    |  ret             |
  | <f2_copy>:        |    |__________________|
  |   ...             |     Instrumentation 
  |___________________|     code (shared lib)
  |                   |
  |  Section headers  |
  |___________________|
   Instrumented Binary

* When instrumenting a binary with trampoline approach, copies of all the original 
  functions are created and are placed in a new code section (.text.instrum) and overwrites
  the first instruction of each original func with a jmp trampoline that jumps to the 
  corresponding copied func. 
  
(SBI) Trampoline Control Flow
  - 1️⃣️ As soon as f1 is called, the trampoline jmps to f1_copy (instrumented version)
  - 2️⃣️ jmp may overwrite following instr to junk bytes. However not executed
  - 3️⃣️ nop instr inserted at every possible instrumentation point in f1_copy. 
       That way, to instrument an instr, overwrite the nop instr at the pt with jmp or
       call to a chunk of instrumentation code
  - 4️⃣️ Replaces all 2-byte relative jmp instr which have 8-bit offset with a corresponding
       5-byte version that has a 32 bit offset. This is required as I shift code around in 
       f1_copy, the offset between jmp intrs and targets may become too large to encode 
       in 8 bits
  - 5️⃣️ Rewrites direct calls such as f2 so it targets instrumented func
  - 6️⃣️ Now assume I instrument every ret instr. To do this SBI overwrites the nop instr 
       reserved for this puspose with a jmp or call to instrumentation code.
  - 7️⃣️ First saves the state (register contents)
  - 8️⃣️ Restores the saved state 
  
* Handling Indirect Control Flow
  - Because indirect controlstr target dynamically computed addrs, no reliable way for
    SBI to statically redirect them.
  - Trampoline approach allows indirect control transfers to flow to original, 
    uninstrumented code and uses trampolines placed in the original code to intercept and
    redirect the control flow back to the instrumented code. 
     _______________            ______________________________
    |.text          |          |.data                         |
    | <f1>:         |        +--  jmptab: f1_case1  <-----------+
    |  jmp f1_copy  |        | |          f1_case2            | |
    |  ...          |        | |______________________________| |
    |               |        | |.text                         | |
    | <f2>:  <--------+      | | <f1>:                        | |
  +--- jmp f2_copy  | |      | |  jmp f1_copy                 | |
  | |  ...          | |      | |  ; junk bytes                | |
  | |_______________| |      +--> f1_case1: ; switch case1    | |
  | |_______________| |        |  f1_case2: ; switch case2    | |
  | |.text.instrum  | |        |______________________________| |
  | | <f1_copy>:    | |        |.text.instrum                 | |
  | |  mov rax, f2  | |        | <f1_copy>:                   | |
  | |  call rax  -----+        |  ...                         | |
  | |  ret          |          |  jmp QWORD PTR [rax*8+jmptab] -+
  | |               |          |  ; switch case 1             |
  +-> <f2_copy>:    |          |  ; switch case 2             |
    |  ...          |          |  ret                         |
    |_______________|          |______________________________|
      indirect call             indirect jump (switch) using jmp table
    
  - By default the addrs stored in jump table all point to the original code. 
    Thus the indirect jmp ends up in the original func with no trampoline. SBI must
    patch the jmp table or place trampoline at every switch case in the original code

# Dynamic Binary Instrumentation (DBI)

* DBI engines monitor binaries (processes) as they execute and instrument the instr stream
  PIN (ex of DBI platform). The DBI tools implement with Pin are Pintools which are 
  shared libraries written in C/C++ using Pin API. Pintools have 2 different types of funcs
  - Instrumentation routines
    tell Pin which instrumentation code to add and where. install callbacks to analysis 
    routines
  - Analysis routines
    contain the actual instrumentation code and called every time an instrumented code runs

* Basic Block 
  - A sequence of consecutive instr in a program that have a single entry point, single
    exit point, and no internal branches out except at the exit
* Trace
  - A sequence of instr with 1 entry point. Typically ends with unconditional branch.
    essentially a sequence of basic blocks that form a continous path through program's
    execution flow. (Determined by Pin)
    
# Profiling with Pin
* Profiling records stats about program's execution (counts num of executed instr & num of 
  basic blocks, funcs, syscalls)

# Automatic Binary Unpacking with Pin
* Executable packers are programs that take a bin and "pack" that binary's code & data
  sections together into a compressed or encrypted data region, producing packed executable
  
=       Original bin            Packed bin             Unpacked bin
=       |          |           |           |           |          |
=     +--- Header  |         +--- Header   |         +--- Header  |
=     | |__________|    ent  | |___________|         | |__________|
= ent | |          |    pt   | | Bootstrap |         | | Bootstrap|
= pt  | |   Data   |         +-->  code    |         +-->  code   |
=     | |__________|           |___________|         +--__________|
=     | |          |           |   Packed  |         | | Unpacked |
=     +-->  Code   |           |code + data|     Jmp | |   data   |
=       |__________|           |___________|     OEP | |__________|
=                                                    | | Unpacked |
=                                                    +-->  code   |
=                                                      |__________|

* When load and execute the packd bin, the bootstrap code extracts the original code & data
  into memory and then transfers control to the OEP (original entry point). Resumes exec
  normally

# Pin Specifics
* Pin observes the program starting from first instr so profiler sees not only application
  code but also instr executed by dynamic loader and shared libs.
* Pin can be run from the start with pin engine or can attach pintool to a running app

* PIN_InitSymbols() 
  - read the application's symbol tables
* PIN_Init
  - initializes Pin and processes Pin's cmd line options & Pintool's options with KNOBs
* Registering the instrumentation routines 
  - IMG_AddInstrumentFunction: registers callback every time a new image (dynamically 
    loaded module, shared lib) is loaded or unloaded
  - TRACE_AddInstrumentFunction: registers callback every trace 
  - INS_AddInstrumentFunction: registers callback every instr
* Registering Syscall Functions
  - PIN_AddSyscallEntryFunction: registers callback when syscall is entered
  - PIN_AddSyscallExitFunction: registers callback when syscall exits
* Registering Fini Function
  - PIN_AddFiniFunction: registers callback when application exits or detach PIN
* PIN_StartProgram
  - starts the application running. No longer possible to register callbacks. never returns

##################### Principles of Dynamic Taint Analysis ####################

* Dynamic Taint Analysis (DTA)
  - program analysis technique to determine the influence that a selected program state
    has on other parts of the program state
  - Taint Sources: program locations where you select data that's interesting to track
  - Taint Sinks: programl locations you check to see whether they can be influenced by
    tainted data
  - Tracking Taint Propogation: Determining how taint propogates from the input operands 
    of an instr to its output operands. Specified by a taint policy
* DTA design factors
  - Taint Granularity: bit, byte, or word granular
  - Taint Colors: multiple taint colors for each taint source
* Shadow memory: region of virtual memory allocated by DTA engine to keep track of memory
  tainting and CPU tainting.

############### Practical Dynamic Taint Analysis w/ LIBDFT ####################


##################### Principles of Symbolic Execution ########################

* Symbolic execution tracks metadata about the program state
  - Symbex executes or emulates application with symbolic values instead of the concrete
    values used when normally run a program
* Symbolic State
  - symbolic expressions: 
  - path constraint, mapping of variables to symbolic expressions



