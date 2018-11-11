require "unicorn_engine"
require "unicorn_engine/arm64_const"

module Lakebed
  class Nso
    def initialize
      @segments = []
      @base_addr = nil
    end

    def self.from_file(file)
      nso = self.new
    end

    def add_segment(content, perm)
      @segments.push([content, perm])
    end

    def each_segment
      @segments.each do |seg|
        yield seg[0], seg[1]
      end
    end

    def set_base_addr(addr)
      @base_addr = addr
    end

    def +(offset)
      return @base_addr + (offset.to_i)
    end
    
    attr_reader :segments
  end

  class NsoBuilder
    def initialize
      @code = String.new
      @data = String.new
    end

    def add_code(str)
      off = @code.size
      @code+= str
      return off
    end

    def add_data(str)
      off = @data.size
      @data+= str
      return off
    end

    def build
      nso = Nso.new
      
      code_pad_size = (@code.size + 0xfff) & ~0xfff
      @code+= 0.chr * (code_pad_size - @code.size)
      nso.add_segment(@code, 5)

      data_pad_size = (@data.size + 0xfff) & ~0xfff
      @data+= 0.chr * (data_pad_size - @data.size)
      nso.add_segment(@data, 3)

      return nso
    end
  end
  
  class Emulator
    BASE = 0x7100000000
    
    def initialize()
      @mu = UnicornEngine::Uc.new(UnicornEngine::UC_ARCH_ARM64, UnicornEngine::UC_MODE_ARM)
      @addr = BASE
    end

    def add_nso(nso)
      nso.set_base_addr(@addr)
      nso.each_segment do |str, perm|
        @mu.mem_map(@addr, str.size)
        @mu.mem_write(@addr, str)
        @mu.mem_protect(@addr, str.size, perm)
        @addr+= str.size
      end
    end

    attr_reader :mu
    
    def begin
      @mu.emu_start(BASE, 0, 0, 10)
    end
  end
end
