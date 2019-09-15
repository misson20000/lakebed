require_relative "constants.rb"

module Lakebed
  module Memory
    class AddressSpaceConfig
      def initialize(base_addr, width, sizes)
        @base_addr = base_addr
        @end_addr = base_addr + (1 << width)
        @width = width

        @sizes = DEFAULT_SIZES.merge(sizes)
      end

      def [](key)
        @sizes[key]
      end
      
      attr_reader :base_addr
      attr_reader :end_addr
      attr_reader :width
    end

    DEFAULT_SIZES = {:heap_region_size => 64 * 1024 * 1024,
                     :alias_region_size => 0x20000 # arbitrary
                    }
    ADDRSPACE_32 = AddressSpaceConfig.new( 0x200000, 32, :stack_region_size => 0x3fe00000)
    ADDRSPACE_36 = AddressSpaceConfig.new(0x8000000, 36, :stack_region_size => 0x78000000)
    ADDRSPACE_39 = AddressSpaceConfig.new(0x8000000, 39, :stack_region_size => 0x80000000)

    def self.addr_aligned?(addr)
      return addr & 0xfff == 0
    end

    def self.size_aligned?(size)
      return size & 0xfff == 0
    end

    class MemoryRange
      def initialize(addr, size)
        @addr = addr
        @size = size
      end

      attr_accessor :addr
      attr_accessor :size
      
      def contains_addr?(addr)
        addr >= @addr && addr < (@addr + @size)
      end

      def overlaps_region?(addr, size)
        return (addr >= @addr && addr < (@addr + @size)) ||
               ((addr + size) > @addr && (addr + size) <= (@addr + @size)) ||
               (@addr >= addr && (@addr+@size) < (addr + size)) ||
               ((@addr + @size) > addr && (@addr + @size) <= (addr + size))
      end

      def encloses_region?(addr, size)
        return (addr >= @addr && addr < (@addr + @size)) &&
               ((addr + size) >= @addr && (addr + size) <= (@addr + @size))
      end
      
      def to_s
        "0x#{@addr.to_s(16)}(+0x#{@size.to_s(16)})"
      end
    end
    
    class MemoryResource
      def initialize(backing, label="unnamed")
        if !Memory::size_aligned?(backing.bytesize) then
          raise "size not page-aligned"
        end

        @backing = backing.force_encoding("ASCII-8BIT")
        @label = label
        @first_segment = Segment.new(0, @backing.bytesize)
      end

      attr_reader :backing

      def principal_slice
        Slice.new(self, 0, @backing.bytesize)
      end

      def carve!(offset, size)
        segs = []
        s = @first_segment

        puts "#{@label}: carving out 0x#{offset.to_s(16)}, +0x#{size.to_s(16)}"
        
        while s do
          if s.contains_addr?(offset) then
            s.split!(offset)
          end

          if s.overlaps_region?(offset, size) then
            segs.push(s)
          end

          if s.contains_addr?(offset + size) then
            s.split!(offset + size)
            break
          end
          
          s = s.after
        end

        s = @first_segment
        while s do
          puts "  #{s}"
          s = s.after
        end
        
        return segs
      end

      def coalesce!
        s = @first_segment
        while s do
          s.verify_integrity
          s.try_coalesce_after!
          s = s.after
        end
      end
      
      def grant_permissions!(offset, size, mapping)
        carve!(offset, size).each do |s|
          puts "#{@label}: granting 0x#{s.addr.to_s(16)} to 0x#{mapping.addr.to_s(16)} from #{s.describe_grantee}"
          s.grant!(mapping)
        end
        coalesce!
      end

      class Segment < MemoryRange
        def initialize(addr, size, before=nil, after=nil, grantee=nil)
          super(addr, size)
          @before = before
          @after = after

          @grantee = grantee
          maybe_lose_grantee!
        end

        attr_accessor :before
        attr_accessor :after
        attr_accessor :grantee

        def describe_grantee
          if @grantee then
            "0x#{@grantee.addr.to_s(16)}, +0x#{@grantee.size.to_s(16)}"
          else
            "nobody"
          end
        end

        def to_s
          "Segment #{super.to_s}: #{describe_grantee}"
        end
        
        def verify_integrity
          if @before then
            if @before.after != self ||
               @before.addr + @before.size != @addr then
              raise "invalid before link"
            end
          end
          
          if @after then
            if @after.before != self ||
               @addr + @size != @after.addr then
              raise "invalid after link"
            end
          end
        end

        def try_coalesce_after!
          if @after && @after.grantee == @grantee then
            @size+= @after.size
            @after = @after.after
            @after.before = self
          end
        end
        
        def split!(addr)
          if !contains_addr?(addr) then
            raise "attempt to split segment at offset out of bounds"
          end

          # don't bother creating zero-size segments
          if addr > @addr then
            new_seg = Segment.new(addr, @addr + @size - addr, self, @after, @grantee)
            @size = addr - @addr
            if @after then
              @after.before = new_seg
            end
            @after = new_seg

            new_seg
          else
            self
          end
        end

        def maybe_lose_grantee!
          puts "#{self} is considering losing grantee..."
          if @grantee then
            puts "  grantee slice covers 0x#{@grantee.slice.addr.to_s(16)}, +0x#{grantee.slice.size.to_s(16)}"
            puts "  we are 0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}"
          end
          if @grantee && !overlaps_region?(@grantee.slice.addr, @grantee.slice.size) then
            puts "  lost!"
            @grantee = nil
          end
        end
        
        def grant!(mapping)
          maybe_lose_grantee!
          
          if @grantee != mapping && @grantee then
            @grantee.set_has_permissions(false)
          end
          @grantee = mapping
          @grantee.set_has_permissions(true)
        end
      end
      
      class Slice < MemoryRange
        def initialize(res, addr, size)
          super(addr, size)
          
          if !Memory::addr_aligned?(addr) then
            raise "offset not page-aligned"
          end
          
          if !Memory::size_aligned?(size) then
            raise "size not page-aligned"
          end
          
          @resource = res
          @addr = addr
          @size = size

          @readers = []
          @writer = nil
        end

        def [](offset, size)
          Slice.new(@resource, @addr + offset, size)
        end
        
        def grant_permissions!(mapping)
          @resource.grant_permissions!(@addr, @size, mapping)
        end
        
        def update(content)
          if content.bytesize != @size then
            raise "updating slice with invalid size"
          end

          @resource.backing[@addr, @size] = content
        end

        def content
          @resource.backing[@addr, @size]
        end
        
        attr_reader :resource
      end
    end

    class Mapping < MemoryRange
      def initialize(as_mgr, addr, size, slice, type, permissions, properties={}, before=nil, after=nil, has_permissions=false)
        super(addr, size)
        @as_mgr = as_mgr
        @slice = slice
        @type = type
        @has_permissions = has_permissions
        @permissions = permissions
        @properties = properties

        @before = before
        @after = after
      end

      attr_accessor :slice
      attr_accessor :type
      attr_accessor :permissions
      attr_accessor :properties
      attr_accessor :before
      attr_accessor :after

      def to_s
        inspect
      end
      
      def inspect
        "Mapping(0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}, type #{@type}, perm #{@permissions}, prop #{@properties})"
      end
      
      def verify_integrity
        if @slice && @slice.size != @size then
          raise "slice size mismatch"
        end
        
        if @before then
          if @before.after != self ||
             @before.addr + @before.size != @addr then
            raise "invalid before link"
          end
        end
        
        if @after then
          if @after.before != self ||
             @addr + @size != @after.addr then
            raise "invalid after link"
          end
        end
      end

      def try_coalesce_after!
        if @after then
          if ((!@after.slice && !@slice) || (
                @after.slice && @slice &&
                @after.slice.resource == @slice.resource &&
                @after.slice.addr == @slice.addr + @slice.size)) &&
             @after.type == @type &&
             @after.permissions == @permissions then
            @size+= @after.size
            if @slice then
              @slice.size+= @after.slice.size
            end
            @after = @after.after
            @after.before = self
          end
        end
      end
      
      def split!(addr)
        if !contains_addr?(addr) then
          raise "attempt to split block at address out of bounds"
        end

        if !Memory::addr_aligned?(addr) then
          raise "attempt to split block at unaligned address"
        end

        # don't bother creating zero-size blocks
        if addr > @addr then
          new_block = Mapping.new(@as_mgr, addr, @addr + @size - addr, @slice ? @slice[addr - @addr, @addr + @size - addr] : nil, @type, @permissions, @properties, self, @after, @has_permissions)
          if @slice then
            @slice.size = addr - @addr
          end
          @size = addr - @addr
          @after.before = new_block
          @after = new_block
          new_block.acquire_permissions!

          new_block
        else
          self
        end
      end

      def acquire_permissions!(perms=0)
        if !@has_permissions && @slice then
          @slice.grant_permissions!(self)
        end
        return @has_permissions && (@perms & perms) != 0
      end

      def set_has_permissions(has_permissions)
        # if we're losing perms, update slice
        if @has_permissions && !has_permissions then
          write_slice
        end

        # if we're gaining perms, update unicorn
        if !@has_permissions && has_permissions then
          read_slice
        end
        
        @has_permissions = has_permissions
        puts "0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}: protecting to #{@has_permissions}"
        @as_mgr.process.mu.mem_protect(@addr, @size, @has_permissions ? Perm::to_uc(@permissions) : 0)
      end
      
      def map_in
        puts "0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}: mapping in"
        @as_mgr.process.mu.mem_map(@addr, @size, 0)
        acquire_permissions!
      end

      def reprotect(perm)
        @permissions = perm
        acquire_permissions!
      end
      
      def read_slice
        puts "0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}: reading slice (size 0x#{@slice.size.to_s(16)})"
        @as_mgr.process.mu.mem_write(@addr, @slice.content)
      end

      def write_slice
        puts "0x#{@addr.to_s(16)}, +0x#{@size.to_s(16)}: writing slice (size 0x#{@slice.size.to_s(16)})"
        @slice.update(@as_mgr.process.mu.mem_read(@addr, @size))
      end

      def map_out
        set_has_permissions(mu, false)
        @as_mgr.process.mu.mem_unmap(@addr, @size)
      end
    end

    class AddressSpaceManager
      def initialize(process, config, head = 0xA0000000)
        @process = process
        @config = config

        mappings = [
          Mapping.new(self, 0, @config.base_addr, nil, MemoryType::Reserved, Perm::None),
          Mapping.new(self, @config.base_addr, @config.end_addr - @config.base_addr, nil, MemoryType::Unmapped, Perm::None),
          Mapping.new(self, @config.end_addr, 0x10000000000000000-@config.end_addr, nil, MemoryType::Reserved, Perm::None)]
        
        # create links
        (mappings.size-1).times do |i|
          mappings[i].after = mappings[i+1]
          mappings[i+1].before = mappings[i]
        end

        @first_mapping = mappings.first
        
        @region_head = head
        @alias_region = alloc_region(@config[:alias_region_size])
        @heap_region = alloc_region(@config[:heap_region_size])
        @stack_region = alloc_region(@config[:stack_region_size])
      end

      attr_reader :process
      attr_reader :config
      attr_reader :alias_region
      attr_reader :heap_region
      attr_reader :stack_region
            
      def within_space?(addr, size)
        return addr >= @config.base_addr && (addr + size) < @config.end_addr
      end
      
      def inspect_addr(addr)
        d = find_mapping(addr)
        if d.properties[:label] then
          b = d.properties[:label_base]
          l = d.properties[:label]
        else
          b = d.addr
          l = "0x" + d.addr.to_s(16)
        end
        "0x" + addr.to_s(16) + " (" + l + " +0x" + (addr - b).to_s(16) + ")"
      end
      
      def find_mapping(addr)
        m = @first_mapping
        while m do
          if m.contains_addr?(addr) then
            return m
          end
          m = m.after
        end
        raise "address space overrun"
      end

      def alloc_region(size)
        reg = MemoryRange.new(@region_head, size)
        @region_head+= size
        @region_head = (@region_head + 0xffffff) & ~0xffffff
        return reg
      end

      def alloc_memory_resource(size, label="unnamed")
        MemoryResource.new((0.chr * size).force_encoding("ASCII-8BIT"), label)
      end

      def wrap_memory_resource(str, label="unnamed")
        MemoryResource.new(str.dup.force_encoding("ASCII-8BIT"), label)
      end

      def carve!(addr, size)
        mappings = []
        m = @first_mapping
        while m do
          if m.contains_addr?(addr) then
            m = m.split!(addr)
          end

          if m.overlaps_region?(addr, size) then
            mappings.push(m)
          end
          
          if m.contains_addr?(addr + size) then
            m.split!(addr + size)
            return mappings
          end
                    
          m = m.after
        end

        raise "carveout end overrun"
      end

      def coalesce!
        m = @first_mapping
        while m do
          m.verify_integrity
          m.try_coalesce_after!
          m = m.after
        end
      end
      
      def map_slice!(addr, slice, type, perm, properties)
        existing_mappings = carve!(addr, slice.size)
        if existing_mappings.size != 1 || existing_mappings[0].type != MemoryType::Unmapped then
          raise "attempt to map slice at 0x#{addr.to_s(16)}, size 0x#{slice.size.to_s(16)} over existing memory (#{existing_mappings})"
        end

        m = existing_mappings[0]
        m.slice = slice
        m.type = type
        m.permissions = perm
        m.properties = properties

        puts "MAPPING IN SLICE..."
        dump_mappings

        m.map_in
      end

      def mirror!(src_as_mgr, src_addr, dst_addr, size, type, perm)
        existing_mappings = carve!(dst_addr, size)
        if existing_mappings.size != 1 || existing_mappings[0].type != MemoryType::Unmapped then
          raise "attempt to mirror over existing memory"
        end

        src = src_as_mgr.carve!(src_addr, size)
        
        m = existing_mappings[0]
        
        src.each do |s|
          puts "mirroring #{s} onto #{m}"
          if m.size > s.size then
            m = m.split!(m.addr + s.size)
          end
          m.size = s.size
          m.slice = s.slice
          m.type = type
          m.permissions = perm
          m.properties = s.properties
          m.map_in
        end
      end

      def unmap!(addr, size)
        carve!(addr, size).each do |m|
          m.map_out
          m.slice = nil
          m.type = MemoryType::Unmapped
          m.permissions = 0
          m.properties = nil
        end
        
        coalesce!
      end

      def reprotect!(addr, size, perm)
        carve!(addr, size).each do |m|
          m.reprotect(perm)
        end
        
        coalesce!
      end

      def dump_mappings
        m = @first_mapping
        while m do
          puts m
          m = m.after
        end
      end
    end
  end
end
