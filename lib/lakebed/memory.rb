require_relative "constants.rb"

module Lakebed
  module Memory
    class AddressSpaceConfig
      def initialize(base_addr, width, stack_region_size)
        @base_addr = base_addr
        @end_addr = base_addr + (1 << width)
        @width = width

        @stack_region_size = stack_region_size
      end

      attr_reader :base_addr
      attr_reader :end_addr
      attr_reader :width
      attr_reader :stack_region_size
    end

    ADDRSPACE_32 = AddressSpaceConfig.new( 0x200000, 32, 0x3fe00000)
    ADDRSPACE_36 = AddressSpaceConfig.new(0x8000000, 36, 0x78000000)
    ADDRSPACE_39 = AddressSpaceConfig.new(0x8000000, 39, 0x80000000)
    
    Allocation = Struct.new(:addr, :size, :attributes) do
      def map(mu)
        mu.mem_map(addr, size, Perm::to_uc(attributes[:perm] || Perm::RW))
      end
      
      def unmap(mu)
        mu.mem_unmap(addr, size)
      end

      def within?(addr, size=0)
        addr >= self.addr && (addr+size) < (self.addr + self.size)
      end
      
      def to_s
        "0x#{addr.to_s(16)}(+0x#{size.to_s(16)}, #{attributes})"
      end
    end

    class AddressSpaceManager      
      def initialize(config, head = 0xA0000000)
        @config = config
        @head = head
        @allocations = []
        @allocations.push(
          Allocation.new(
            0, @head, {
              :label => "beginning of address space",
              :memory_type => MemoryType::Unmapped,
              :permission => Perm::None
            }))
      end

      attr_reader :config
      
      def addr_aligned?(addr)
        return addr & 0xfff == 0
      end

      def size_aligned?(size)
        return size & 0xfff == 0
      end
      
      def within_space?(addr, size)
        return addr >= @config.base_addr && (addr + size) < @config.end_addr
      end
      
      def inspect_addr(addr)
        d = describe(addr)
        if d.attributes[:label] then
          l = d.attributes[:label]
        else
          l = "0x" + d.addr.to_s(16)
        end
        "0x" + addr.to_s(16) + " (" + l + " +0x" + (addr - d.addr).to_s(16) + ")"
      end
      
      def describe(addr)
        alloc = @allocations.bsearch do |alloc|
          if addr < alloc.addr then
            -1
          elsif addr < (alloc.addr + alloc.size) then
            0
          else
            1
          end
        end
        if alloc && addr >= alloc.addr && addr < (alloc.addr + alloc.size) then
          return alloc
        else
          return Allocation.new(
                   @head, ~@head, {
                     :label => "end of address space",
                     :memory_type => MemoryType::Unmapped,
                     :permission => Perm::None})
        end
      end
      
      def alloc(size, attributes)
        alloc = Allocation.new(@head, size, attributes)
        @allocations.push(alloc)
        @head+= size
        @head = (@head + 0xffffff) & ~0xffffff
        return alloc
      end

      def dump
        @allocations.each do |a|
          puts a
        end
      end
      
      def force(addr, size, attributes)
        @allocations.each do |a|
          if a.addr == 0 then
            next # don't care about overlaps with first region
          end
          if (a.addr >= addr && a.addr < (addr + size)) || # if a's beginning overlaps our region
             ((a.addr + a.size) >+ addr && (a.addr + a.size) < (addr + size)) | # if a's end overlaps our region
             (addr >= a.addr && addr < (a.addr + a.size)) || # if our beginning overlaps a
             ((addr + size) >= a.addr && (addr + size) < (a.addr + a.size)) then # if our end overlaps a
            raise "attempting to insert 0x#{addr.to_s(16)}(+0x#{size.to_s(16)}, #{attributes}), but overlaps with #{a}"
          end
        end
        i = @allocations.find_index do |a|
          a.addr > addr
        end || -1
        alloc = Allocation.new(addr, size, attributes)
        @allocations.insert(i, alloc)
        if i == 1 then
          @allocations[0].size = addr
        end
        return alloc
      end
    end
  end
end
