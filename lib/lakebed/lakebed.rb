require "unicorn_engine"
require "unicorn_engine/arm64_const"
require "digest"
require "lz4-ruby"

require_relative "elf.rb"

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

    attr_reader :base_addr
    attr_reader :segments
  end

  class NsoBuilder
    def initialize(params={})
      @sections = []
      @symbols = {}
      @params = params
      
      if !@params.include?(:prelude) || @params[:prelude] then
        # b 8
        # .word _mod0
        first_sec = add_section("\x02\x00\x00\x14BAD!", :text)
        first_sec.add_static_relocation(4, Elf::R_AARCH64_PREL32, "_mod0", 4)
      end
    end

    class Location
      def initialize(section, offset)
        @section = section
        @offset = offset
      end

      def to_i
        @section.nso_location + @offset
      end
      
      def to_location
        self
      end
      
      attr_reader :section
      attr_reader :offset
    end

    class Relocation
      def initialize(location, type, symbol, addend)
        @location = location
        @type = type
        @symbol = symbol
        @addend = addend
      end

      def run(content, content_base, symbols)
        s = symbols[@symbol].to_i
        a = @addend
        p = @location.to_i

        #puts "s: #{s}, a: #{a}, p: #{p}"
        
        data = case @type
               when Elf::R_AARCH64_ABS64
                 raise "can't be run statically"
               when Elf::R_AARCH64_ABS32
                 raise "can't be run statically"
               when Elf::R_AARCH64_ABS16
                 raise "can't be run statically"
               when Elf::R_AARCH64_PREL64
                 [s + a - p].pack("Q<")
               when Elf::R_AARCH64_PREL32
                 [s + a - p].pack("L<")
               when Elf::R_AARCH64_PREL16
                 [s + a - p].pack("S<")
               end

        content[p - content_base, data.size] = data
      end
      
      attr_reader :location
      attr_reader :type
      attr_reader :symbol
      attr_reader :addend
    end
    
    class Section
      def initialize(content, segment)
        @content = content
        @segment = segment
        @static_relocations = []
        @dynamic_relocations = []
      end

      attr_reader :content
      attr_reader :segment
      attr_reader :static_relocations
      attr_reader :dynamic_relocations
      attr_accessor :nso_location
      
      def +(offset)
        Location.new(self, offset)
      end

      def to_location(offset=0)
        Location.new(self, offset)
      end

      def add_static_relocation(offset, type, symbol, addend)
        rel = Relocation.new(to_location(offset), type, symbol, addend)
        @static_relocations.push(rel)
        rel
      end

      def run_static_relocations(string, string_base, symbols)
        @static_relocations.each do |reloc|
          reloc.run(string, string_base, symbols)
        end
      end
    end
    
    # segment is :text, :rodata, or :data
    def add_section(content, segment)
      section = Section.new(content.b, segment)
      @sections.push(section)
      return section
    end

    def add_symbol(name, location)
      @symbols[name] = location.to_location
    end
    
    def build
      nso = Nso.new

      lc = 0
      
      {:text => 5, :rodata => 1, :data => 3}.map do |segment, permission|
        # pad to page
        lc += 0xfff
        lc &= ~0xfff
        
        segment_base = lc
        content = String.new
        @sections.each do |sec|
          if sec.segment == segment then
            sec.nso_location = lc
            content = content + sec.content
            lc+= sec.content.bytesize
          end
        end
        [segment, permission, segment_base, content]
      end.each do |params|
        segment, permission, segment_base, content = params
        @sections.each do |sec|
          if sec.segment == segment then
            sec.run_static_relocations(content, segment_base, @symbols)
          end
        end
        content_pad_size = (content.bytesize + 0xfff) & ~0xfff
        content+= 0.chr * (content_pad_size - content.bytesize)
        nso.add_segment(content, permission)
      end

      return nso
    end
  end
  
  class Emulator
    STACK_TOP_ADDR = 0x70000000
    BASE_ADDR = 0x71000000
    
    def initialize(stack_size = 0x10000)
      @mu = UnicornEngine::Uc.new(UnicornEngine::UC_ARCH_ARM64, UnicornEngine::UC_MODE_ARM)
      @addr = BASE_ADDR

      @segments = []
      @pending_error = nil
      @svc_hooks = {}

      @mu.reg_write(UnicornEngine::UC_ARM64_REG_PC, BASE_ADDR)
      
      # setup stack
      @mu.mem_map(STACK_TOP_ADDR - stack_size, stack_size)
      @mu.reg_write(UnicornEngine::UC_ARM64_REG_SP, STACK_TOP_ADDR)
      
      # enable NEON
      @mu.reg_write(UnicornEngine::UC_ARM64_REG_CPACR_EL1, 3 << 20)

      # add exception hook
      @mu.hook_add(
        UnicornEngine::UC_HOOK_INTR, Proc.new do |uc, value, ud|
          begin
            syndrome = @mu.query(UnicornEngine::UC_QUERY_EXCEPTION_SYNDROME)
            ec = syndrome >> 26
            iss = syndrome & ((1 << 24)-1)
            
            if ec == 0x15 then # SVC instruction taken from AArch64
              if @svc_hooks[iss] then
                @svc_hooks[iss].call(iss)
              else
                call_hle_svc(iss)
              end
            else
              throw GuestExceptionError.new(self, "exception (ec: 0b#{ec.to_s(2)}, iss: 0x#{iss.to_s(16)})")
            end
          rescue => e
            @pending_error = e
            @mu.emu_stop
          end
        end)

      # add unmapped write hook
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_WRITE_UNMAPPED, Proc.new do |uc, access, address, size, value|
          @pending_error = UnmappedWriteError.new(self, [value].pack("Q<"), address)
          @mu.emu_stop
        end)
    end

    class GuestExceptionError < RuntimeError
      def initialize(emu, message)
        @emu = emu
        super(message + " (pc = 0x#{emu.pc.to_s(16)})")
      end
    end
    
    class UnmappedWriteError < GuestExceptionError
      def initialize(emu, value, address)
        super(emu, "attempted to write #{value.unpack("H*").first} to 0x#{address.to_s(16)}")
        @value = value
        @address = address
      end
    end

    class UnknownSvcError < GuestExceptionError
      def initialize(emu, id)
        super(emu, "attempted to call unknown svc 0x#{id.to_s(16)}")
        @id = id
      end
    end

    def add_nso(nso)
      nso.set_base_addr(@addr)
      nso.each_segment do |str, perm|
        if str.bytesize > 0 then
          @segments.push(
            {
              :base => @addr,
              :size => str.bytesize,
              :memory_type => {1 => 3, 3 => 4, 5 => 3}[perm],
              :memory_attribute => 0,
              :permission => perm})
          @mu.mem_map(@addr, str.bytesize)
          @mu.mem_write(@addr, str)
          @mu.mem_protect(@addr, str.bytesize, perm)
          @addr+= str.bytesize
        end
      end
      return nso
    end

    attr_reader :mu
    
    def begin(limit=10000)
      @pending_error = nil
      @mu.emu_start(pc, 0, 0, limit)
      if @pending_error then
        throw @pending_error
      end
    end

    def x(no)
      @mu.reg_read(UnicornEngine::UC_ARM64_REG_X0 + no)
    end

    (0..30).each do |num|
      define_method(("x" + num.to_s).to_sym) do |val=nil|
        if val != nil then
          @mu.reg_write(UnicornEngine::UC_ARM64_REG_X0 + num, val.to_i)
        else
          @mu.reg_read(UnicornEngine::UC_ARM64_REG_X0 + num)
        end
      end
    end

    (0..30).each do |num|
      define_method(("x" + num.to_s + "=").to_sym) do |val|
        @mu.reg_write(UnicornEngine::UC_ARM64_REG_X0 + num, val.to_i)
      end
    end

    def pc
      @mu.reg_read(UnicornEngine::UC_ARM64_REG_PC)
    end

    def hook_svc(id, &block)
      @svc_hooks[id] = block
    end

    def unhook_svc(id)
      @svc_hooks.delete(id)
    end
    
    def call_hle_svc(id)
      case id
      when 0 # nullsvc
      when 6 # QueryMemory
        meminfo = x0
        addr = x2

        unmapped = {
          :base => 0,
          :size => @segments.first[:base],
          :memory_type => 0,
          :permission => 0}

        segment = @segments.reverse_each.find do |seg|
          seg[:base] <= addr
        end || unmapped

        if addr >= segment[:base] + segment[:size] then
          segment = {
            :base => segment[:base] + segment[:size],
            :size => ~(segment[:base] + segment[:size]) + 1,
            :memory_type => 0,
            :permission => 0}
        end

        @mu.mem_write(meminfo, [
                        segment[:base],
                        segment[:size],
                        segment[:memory_type],
                        0,
                        segment[:permission],
                        0, 0, 0
                      ].pack("Q<Q<L<L<L<L<L<L<"))
        
        x0(0)
        x1(0)

        @last_query_segment = segment
        return segment
      else
        raise UnknownSvcError.new(self, id)
      end
    end

    attr_reader :last_query_segment
  end
end
