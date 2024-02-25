# built-in imports
from collections import namedtuple
from pathlib import Path
from typing import Optional, Generator, Tuple, Dict, Union
import logging

# local imports
from tritondse.loaders import Loader, LoadableSegment
from tritondse.types import Addr, Architecture, Platform, ArchMode, PathLike, Perm, Endian
from tritondse.arch import ARCHS

# https://github.com/skelsec/minidump/
from minidump.minidumpfile import *
from minidump.streams.ContextStream import *

def cpustate_from_CONTEXT(tc):
  if type(tc) ==  CONTEXT:
    return {"rax":tc.Rax,
            "rbx":tc.Rbx,
            "rcx":tc.Rcx,
            "rdx":tc.Rdx,
            "rsp":tc.Rsp,
            "rbp":tc.Rbp,
            "rsi":tc.Rsi,
            "rdi":tc.Rdi,
            "rip":tc.Rip,
            "r8": tc.R8,
            "r9": tc.R9,
            "r10":tc.R10,
            "r11":tc.R11,
            "r12":tc.R12,
            "r13":tc.R13,
            "r14":tc.R14,
            "r15":tc.R15,
            "cs": tc.SegCs,
            "fs": tc.SegFs,
            "gs": tc.SegGs,
            "ss": tc.SegSs
            }
  elif type(tc) == WOW64_CONTEXT:
    return {"eax":tc.Eax,
            "ebx":tc.Ebx,
            "ecx":tc.Ecx,
            "edx":tc.Edx,
            "esp":tc.Esp,
            "ebp":tc.Ebp,
            "esi":tc.Esi,
            "edi":tc.Edi,
            "eip":tc.Eip,
            "cs": tc.SegCs,
            "fs": tc.SegFs,
            "gs": tc.SegGs,
            "ss": tc.SegSs
            }
  return {} # unknown arch ...

class MinidumpLoader(Loader):
    """
    Minidump loader. It helps loading a Windows process memory dump
    in DSE memory space, with the various attributes like architecture etc.
    For the moment, only handle X86_64 arch...
    """

    def get_active_thread(self):
      """
      get the thread object throwing the ExceptionAddress
      """
      exceptions=self.md.exception.exception_records
      if len(exceptions)==0:
        return None
      threadId=exceptions[0].ThreadId
      for t in self.md.threads.threads:
        if t.ThreadId==threadId:
          return t
      return None

    def get_module_by_address(self, addr):
        """
        get the module name, if any, matching a memory address
        """
        for m in self.md.modules.modules:
            if m.baseaddress<=addr<=m.baseaddress+m.size:
                return m.name
        return None

    def __init__(self,
                 path: PathLike):
        super(MinidumpLoader, self).__init__(path)
        self.path: Path = Path(path)  #: MemoryDump file path
        if not self.path.is_file():
            raise FileNotFoundError(f"file {path} not found (or not a file)")

        md = MinidumpFile.parse(path)
        self.md = md
        
        if md.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
          self._architecture =  Architecture.X86
        elif md.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
          self._architecture =  Architecture.X86_64_MS
        else:
          raise Error("Unsupported Minidump architecture")

        self._arch_mode = None
        self._archinfo = ARCHS[self._architecture]

        main_module = md.modules.modules[0]
        logging.info(f"Loading minidump for process {main_module.name} at {main_module.baseaddress:016x} ")
        
        self.main_module = main_module

        # mapping segments for this module
        vmmap = []
        memsize_mapped = 0
        for mdms in md.memory_segments_64.memory_segments:
            md.file_handle.seek(mdms.start_file_address)
            blob = md.file_handle.read(mdms.size)            
            vmmap.append(LoadableSegment(mdms.start_virtual_address,len(blob),Perm.R|Perm.W|Perm.X,blob))
            memsize_mapped += mdms.size

        logging.info(f"Mapped {len(vmmap)} segments for a total of {memsize_mapped} bytes")

        self.vmmap = vmmap

        # init cpustate from threadcontext
        active_thread = self.get_active_thread()
        cs = cpustate_from_CONTEXT(active_thread.ContextObject)
        self._cpustate = cs
        
        # We directly map GS to the current Thread TEB address,
        # this way code like `mov rax, qword ptr gs:[0x58]` will be correctly evaluated !
        if  self._architecture ==  Architecture.X86:
          cs['fs']=active_thread.Teb
        elif self._architecture == Architecture.X86_64_MS:
          cs['gs']=active_thread.Teb
        else:
          raise Error("Unexpected control flow \o\ /o/")




    @property
    def name(self) -> str:
        """ Name of the loader"""
        return f"{self.main_module.name}"

    @property
    def architecture(self) -> Architecture:
        """
        Architecture enum representing program architecture.

        :rtype: Architecture
        """
        return self._architecture


    @property
    def arch_mode(self) -> ArchMode:
        """
        ArchMode enum representing the starting mode (e.g Thumb for ARM).

        :rtype: ArchMode
        """
        return self._arch_mode


    @property
    def entry_point(self) -> Addr:
        """
        Program entrypoint address as defined in the binary headers

        :rtype: :py:obj:`tritondse.types.Addr`
        """
        return self.cpustate[self._archinfo.pc_reg]


    def memory_segments(self) -> Generator[LoadableSegment, None, None]:
        """
        In the case of a monolithic firmware, there is a single segment.
        The generator returns a single tuple with the load address and the content.

        :return: Generator of tuples addrs and content
        """
        return self.vmmap

    @property
    def cpustate(self) -> Dict[str, int]:
        """
        Provide the initial cpu state in the format of a dictionary of
        {"register_name" : register_value}
        """
        return self._cpustate

    @property
    def platform(self) -> Optional[Platform]:
        """
        Platform of the binary.

        :return: Platform
        """
        return self._platform

    @property
    def endianness(self) -> Endian:
        return Endian.LITTLE            # TODO: Check if a Windbg dump could be else ? 

        
    def is_mainmodule_address(self,address):
        """
        :return: True if the adress belongs to the main module memory segment
        """
        return self.main_module.baseaddress <= address <= self.main_module.baseaddress+self.main_module.size

