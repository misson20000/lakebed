module Lakebed
  module Elf
    R_AARCH64_ABS64 = 257
    R_AARCH64_ABS32 = 258
    R_AARCH64_ABS16 = 259
    R_AARCH64_PREL64 = 260
    R_AARCH64_PREL32 = 261
    R_AARCH64_PREL16 = 262
    R_AARCH64_COPY = 1024
    R_AARCH64_GLOB_DAT = 1025
    R_AARCH64_JUMP_SLOT = 1026
    R_AARCH64_RELATIVE = 1027
    R_AARCH64_TLS_DTPREL64 = 1028
    R_AARCH64_TLS_DTPMOD64 = 1029
    R_AARCH64_TLS_TPREL64 = 1030
    R_AARCH64_TLSDESC = 1031
    R_AARCH64_IRELATIVE = 1032

    def self.relocation_size(r)
      case r
      when R_AARCH64_COPY..R_AARCH64_IRELATIVE
        return 8
      else
        raise "unknown relocation size for #{r}"
      end
    end
    
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
  end
end
