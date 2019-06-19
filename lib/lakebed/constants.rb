module Lakebed
  module MemoryType
    Unmapped = 0x0
    Io = 0x1
    Normal = 0x2
    CodeStatic = 0x3
    CodeMutable = 0x4
    Heap = 0x5
    SharedMemory = 0x6
    Alias = 0x7
    ModuleCodeStatic = 0x8
    ModuleCodeMutable = 0x9
    Ipc = 0xa
    Stack = 0xb
    ThreadLocal = 0xc
    TransferMemoryIsolated = 0xd
    TransferMemory = 0xe
    ProcessMemory = 0xf
    Reserved = 0x10
    NonSecureIpc = 0x11
    NonDeviceIpc = 0x12
    KernelStack = 0x13
    CodeReadOnly = 0x14
    CodeWritable = 0x15
  end
  
  module Perm
    None = 0
    R = 1
    W = 2
    X = 4

    RW = R | W
    RX = R | X
    RWX = R | W | X

    def self.to_uc(perm)
      uc = 0
      if perm & R
        uc|= UnicornEngine::UC_PROT_READ
      end
      if perm & W
        uc|= UnicornEngine::UC_PROT_WRITE
      end
      if perm & X
        uc|= UnicornEngine::UC_PROT_EXEC
      end
      return uc
    end
  end
  
  module InfoId
    AllowedCpuIdBitmask = 0
    AllowedThreadPrioBitmask = 1
    AliasRegionBaseAddr = 2
    AliasRegionSize = 3
    HeapRegionBaseAddr = 4
    HeapRegionSize = 5
    TotalMemoryAvailable = 6
    TotalMemoryUsage = 7
    IsCurrentProcessBeingDebugged = 8
    ResourceLimitHandle = 9
    IdleTickCount = 10
    RandomEntropy = 11

    # 2.0.0+
    AddressSpaceBaseAddr = 12
    AddressSpaceSize = 13
    StackRegionBaseAddr = 14
    StackRegionSize = 15

    # 3.0.0+
    PersonalMmHeapSize = 16
    PersonalMmHeapUsage = 17
    TitleId = 18

    # 4.0.0-4.1.0
    PrivilegedProcessId = 19

    # 5.0.0+
    UserExceptionContextAddr = 20

    # 6.0.0+
    TotalMemoryAvailableWIthoutMmHeap = 21
    TotalMemoryUsedWithoutMmHeap = 22

    # ???
    Performance = 0xF0000002
  end

  class TargetVersion
    def initialize(target, numeric)
      @target = target
      @numeric = numeric
    end

    attr_reader :target
    attr_reader :numeric

    include Comparable

    def to_i
      @numeric
    end
    
    def <=>(other)
      @numeric <=> other.to_i
    end

    def ams_target
      if @numeric < PK1_200 then return 1 end
      if @numeric < PK1_300 then return 2 end
      if @numeric < PK1_400 then return 3 end
      if @numeric < PK1_500 then return 4 end
      if @numeric < PK1_600 then return 5 end
      if @numeric < PK1_620 then return 6 end
      if @numeric < PK1_700 then return 7 end
      if @numeric < PK1_800 then return 8 end
      # TODO: if @numeric < PK1_810 then return 9 end
      return 10
    end

    PK1_100 =      0x1c2
    PK1_200 =    0x10104
    PK1_210 =    0x2005a
    PK1_300 =  0xc00019a
    PK1_301 =  0xc010032
    PK1_302 =  0xc020014
    PK1_400 = 0x100000c8
    PK1_410 = 0x10100028
    PK1_500 = 0x140001ae
    PK1_510 = 0x14100050
    PK1_600 = 0x1800014a
    PK1_620 = 0x18200028
    PK1_700 = 0x1c0000b4
    PK1_701 = 0x1c01001e
    PK1_800 = 0x20000212
  end

  module ConfigItem # for smcGetConfigUser
    ExosphereVersion = 65000
  end
end
