require_relative "error.rb"
require_relative "sync.rb"
require_relative "hipc.rb"

module Lakebed
  class Process
    def svc(id)
      case id
      when 0x5
        svc_unmap_memory
      when 0x6
        svc_query_memory
      when 0xb
        svc_sleep_thread
      when 0x18
        svc_wait_synchronization
      when 0x19
        svc_cancel_synchronization
      when 0x1f
        svc_connect_to_named_port
      when 0x24
        svc_get_process_id
      when 0x27
        svc_output_debug_string
      when 0x29
        svc_get_info
      when 0x70
        svc_create_port
      when 0x71
        svc_manage_named_port
      when 0x7f
        svc_call_secure_monitor
      else
        raise UnknownSvcError.new(self, id)
      end
    end

    def svc_unmap_memory
      dst_addr = x0
      src_addr = x1
      size = x2

      # skip fail-fast for certain sad paths when libnx is abusing us
      # to determine address space size
      is_libnx_quirk =
        (dst_addr == 0xFFFFFFFFFFFFE000) &&
        (src_addr == 0xFFFFFE000) &&
        (size == 0x1000)
      
      if !@as_mgr.addr_aligned?(dst_addr) || !@as_mgr.addr_aligned?(src_addr) then
        raise ResultError.new(0xcc01)
      end

      if size == 0 || !@as_mgr.size_aligned?(size) then
        raise ResultError.new(0xca01)
      end

      if !@as_mgr.within_space?(src_addr, size) then
        if is_libnx_quirk then
          x0(0xd401)
          return
        else
          raise ResultError.new(0xd401)
        end
      end

      if !@stack_region.within?(dst_addr, size) then
        if is_libnx_quirk then
          x0(0xdc01)
          return
        else
          raise ResultError.new(0xdc01)
        end
      end

      raise "nyi"
    end
    
    def svc_query_memory
      meminfo = x0
      addr = x2

      alloc = @as_mgr.describe(addr)
      @mu.mem_write(meminfo, [
                      alloc.addr,
                      alloc.size,
                      alloc.attributes[:memory_type] || 0,
                      0,
                      alloc.attributes[:permission] || 0,
                      0, 0, 0
                    ].pack("Q<Q<L<L<L<L<L<L<"))
      
      x0(0)
      x1(0)
    end

    def svc_sleep_thread
      puts "sleep #{x0}"
    end

    def svc_wait_synchronization
      handles = @mu.mem_read(x1, x2 * 4).unpack("L<*")
      timeout = x3

      objects = handles.map do |h|
        @handle_table.get_strict(h, Waitable)
      end

      puts "svcWaitSynchronization(\n  " +
           (objects.map do |obj| obj.inspect end).join(",\n  ") + ")"
      
      suspension = @current_thread.suspend("svcWaitSynchronization")
      procs = []
      earlywake = true
      objects.each_with_index.map do |obj, i|
        procs.push(
          [
            obj,
            obj.wait do
              puts "got signal from #{obj}"
              suspension.release do
                x0(0)
                x1(i)
              end
              procs.each do |pr|
                pr[0].unwait(pr[1])
              end
              if earlywake then
                return
              end
            end
          ])
      end
      earlywake = false
    end
    
    def svc_cancel_synchronization
      if x0 == 0 then
        # libstratosphere does this sometimes...
        x0(0xe401)
        return
      end
      
      thread = @handle_table.get_strict(x0, LKThread)
      thread.cancel_synchronization
      x0(0)
    end
    
    def svc_connect_to_named_port
      name = @mu.mem_read(x1, 12).unpack("Z12")[0]
      if name.bytesize >= 12 then
        raise ResultError.new(0xee01)
      end

      if @kernel.named_ports.key?(name) then
        port = @kernel.named_ports[name]
      else
        raise ResultError.new(0xf201, "trying to connect to named port #{name}")
      end

      suspension = @current_thread.suspend("connecting to named port \"#{name}\"")
      port.connect do |sess|
        suspension.release do
          x0(0)
          x1(@handle_table.insert(sess))
        end
      end
    end

    def svc_get_process_id
      x1(@handle_table.get_strict(x1, Process).pid)
      x0(0)
    end
    
    def svc_output_debug_string
      puts "DEBUG: " + @mu.mem_read(x0, x1)
    end

    # this one needs a good impl for version detection shenanigans...
    def svc_get_info
      info_id = x1
      handle = x2
      info_sub_id = x3

      if handle != 0 then
        if handle == 0xffff8001 then
          object = self
        elsif handle == 0xffff8000 then
          object = @current_thread
        else
          #puts "handle: #{handle.to_s(16)}"
          #object = @handle_table.get(handle)
        end
        if object == nil then
          raise ResultError.new(0xe401)
        end
      end

      x0(0) # OK

      # Note the distinction between infos that are unknown,
      # and those that are known to exist but unimplemented.
      
      case info_id
      when InfoId::AllowedCpuIdBitmask,
           InfoId::AllowedThreadPrioBitmask
        raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
      when InfoId::AliasRegionBaseAddr
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.alias_region.addr)
        return
      when InfoId::AliasRegionSize
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.alias_region.size)
        return
      when InfoId::HeapRegionBaseAddr
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.heap_region.addr)
        return
      when InfoId::HeapRegionSize
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.heap_region.size)
        return
      when InfoId::TotalMemoryAvailable,
           InfoId::TotalMemoryUsage
        raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
      when InfoId::IsCurrentProcessBeingDebugged
        if handle != 0 then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(0)
        return
      when InfoId::ResourceLimitHandle,
           InfoId::IdleTickCount,
           InfoId::RandomEntropy
        raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_200 then
        case info_id
        when InfoId::AddressSpaceBaseAddr,
             InfoId::AddressSpaceSize,
             InfoId::StackRegionBaseAddr,
             InfoId::StackRegionSize
          raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
        end
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_300 then
        case info_id
        when InfoId::PersonalMmHeapSize,
             InfoId::PersonalMmHeapUsage,
             InfoId::TitleId
          raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
        end
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_400 && @kernel.environment.target_firmware < TargetVersion::PK1_500 then
        case info_id
        when InfoId::PrivilegedProcessId
          raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
        end
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_500 then
        case info_id
        when InfoId::UserExceptionContextAddr
          raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
        end
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_600 then
        case info_id
        when InfoId::TotalMemoryAvailableWithoutMmHeap,
             InfoId::TotalMemoryUsedWithoutMmHeap
          raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
        end
      end

      puts "WARNING: target getting unsupported info #{info_id}"
      x0(0xf001) # let this one past strict error handling
    end

    def svc_create_port
      # TODO: make sure this is right...
      if x3 != 0 then
        raise "light sessions not supported"
      end
      
      name = @mu.mem_read(x4, 12).unpack("Z12")[0]
      if name.bytesize >= 12 then
        raise ResultError.new(0xee01)
      end

      port = Port.new(name, x2)
      x0(0)
      x1(@handle_table.insert(port.server))
      x2(@handle_table.insert(port.client))
    end
    
    def svc_manage_named_port
      # TODO: make sure this is right...
      name = @mu.mem_read(x1, 12).unpack("Z12")[0]
      if name.bytesize >= 12 then
        raise ResultError.new(0xee01)
      end

      port = Port.new(name, x2)
      @kernel.named_ports[name] = port
      x0(0)
      x1(@handle_table.insert(port.server))
    end
    
    def svc_call_secure_monitor
      smc_sub_id = x0
      smc_args = [x1, x2, x3, x4, x5, x6, x7]
      puts "SMC[0x#{smc_sub_id.to_s(16)}](#{smc_args.inspect})"
      @kernel.secure_monitor.call(self, smc_sub_id, smc_args).each_with_index do |v, i|
        puts "  x#{i} => 0x#{v.to_s(16)}"
        x(i, v)
      end
    end
  end
end
