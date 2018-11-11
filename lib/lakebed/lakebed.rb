require "unicorn_engine"
require "unicorn_engine/arm64_const"
require "digest"
require "lz4-ruby"

module Lakebed
  class Nso
    def initialize
      @segments = []
      @base_addr = nil
    end

    def self.from_file(file)
      magic, version, reserved, flags = file.read(0x10).unpack("a4L<L<L<")
      if magic != "NSO0" then
        raise "invalid NSO magic"
      end
      if version != 0 then
        raise "invalid NSO version"
      end

      text_segheader, rodata_segheader, data_segheader = 3.times.map do
        Hash[[:file_offset, :memory_offset, :decompressed_size, :extra].zip(
          file.read(0x10).unpack("L<L<L<L<"))]
      end

      build_id = file.read(0x20)
      text_compressed_size, rodata_compressed_size, data_compressed_size = file.read(0xc).unpack("L<L<L<")
      file.read(0x1c) # reserved
      file.read(0x18) # irrelevant

      hashes = 3.times.map do
        file.read(0x20)
      end

      if file.pos != 0x100 then
        raise "invalid header size"
      end

      file.seek(text_segheader[:file_offset])
      text_compressed = file.read(text_compressed_size)

      file.seek(rodata_segheader[:file_offset])
      rodata_compressed = file.read(rodata_compressed_size)

      file.seek(data_segheader[:file_offset])
      data_compressed = file.read(data_compressed_size)

      digest = Digest::SHA2.new(256)
      
      text, rodata, data = [
        text_compressed, rodata_compressed, data_compressed].each_with_index.map do |compressed, i|
        segheader = [text_segheader, rodata_segheader, data_segheader][i]
        if flags[i] then # is compressed
          decompressed = LZ4::Raw::decompress(compressed, segheader[:decompressed_size]).first
        else
          decompressed = compressed
        end
        if flags[i+3] then # check hash
          actual_hash = digest.digest(decompressed)
          if actual_hash != hashes[i] then
            raise "hash mismatch on #{["text", "rodata", "data"][i]} segment (#{actual_hash.unpack("H*").first} != #{hashes[i].unpack("H*").first})"
          end
        else
          puts "skipping hash check"
        end
        if decompressed.bytesize != segheader[:decompressed_size] then
          raise "decompressed size mismatch"
        end
        decompressed
      end

      nso = self.new
      nso.add_segment(text, 5)
      nso.add_segment(rodata, 1)
      nso.add_segment(data + (0.chr * data_segheader[:extra]), 3)
      return nso
   end

    def add_segment(content, perm)
      target_size = (content.bytesize + 0xfff) & ~0xfff
      content+= 0.chr * (target_size - content.bytesize)

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
      off = @code.bytesize
      @code+= str
      return off
    end

    def add_data(str)
      off = @data.bytesize
      @data+= str
      return off
    end

    def build
      nso = Nso.new
      
      code_pad_size = (@code.bytesize + 0xfff) & ~0xfff
      @code+= 0.chr * (code_pad_size - @code.bytesize)
      nso.add_segment(@code, 5)

      data_pad_size = (@data.bytesize + 0xfff) & ~0xfff
      @data+= 0.chr * (data_pad_size - @data.bytesize)
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
