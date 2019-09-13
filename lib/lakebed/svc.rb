require "hexdump"
require_relative "error.rb"
require_relative "sync.rb"
require_relative "hipc.rb"

module Lakebed
  class Process
    def svc(id)
      case id
      when 0x4
        svc_map_memory
      when 0x5
        svc_unmap_memory
      when 0x6
        svc_query_memory
      when 0x8
        svc_create_thread
      when 0xb
        svc_sleep_thread
      when 0xc
        svc_get_thread_priority
      when 0xd
        svc_set_thread_priority
      when 0x16
        svc_close_handle
      when 0x18
        svc_wait_synchronization
      when 0x19
        svc_cancel_synchronization
      when 0x1d
        svc_signal_process_wide_key
      when 0x1f
        svc_connect_to_named_port
      when 0x21
        svc_send_sync_request
      when 0x24
        svc_get_process_id
      when 0x25
        svc_get_thread_id
      when 0x27
        svc_output_debug_string
      when 0x29
        svc_get_info
      when 0x41
        svc_accept_session
      when 0x43
        svc_reply_and_receive
      when 0x45
        svc_create_event
      when 0x6f
        svc_get_system_info
      when 0x70
        svc_create_port
      when 0x71
        svc_manage_named_port
      when 0x72
        svc_connect_to_port
      when 0x7f
        svc_call_secure_monitor
      else
        raise UnknownSvcError.new(self, id)
      end
    end

    def svc_map_memory
      dst_addr = x0
      src_addr = x1
      size = x2

      # TODO: check that we're in the stack region
      alloc = @as_mgr.force(
        dst_addr, size,
        {:label => "remapped",
         :memory_type => MemoryType::Stack,
         :permission => Perm::RW})
      alloc.map(@mu)

      x0(0)
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

    def svc_create_thread
      thread = LKThread.new(self, {:entry => x1, :sp => x3})
      thread.gprs[0] = x2 # context
      thread.priority = x4

      # x5: processor id is ignored

      x0(0)
      x1(@handle_table.insert(thread))
    end
    
    def svc_sleep_thread
      Logger.log_for_thread(@current_thread, "sleep #{x0}")
    end

    def svc_get_thread_priority
      thread = @handle_table.get_strict(x1, LKThread)
      x0(0)
      x1(thread.priority)
    end

    def svc_set_thread_priority
      thread = @handle_table.get_strict(x0, LKThread)
      thread.priority = x1
      x0(0)
    end

    def svc_close_handle
      @handle_table.close(x0)
      x0(0)
    end
    
    def svc_wait_synchronization
      handles = @mu.mem_read(x1, x2 * 4).unpack("L<*")
      timeout = x3

      objects = handles.map do |h|
        @handle_table.get_strict(h, Waitable)
      end

      Logger.log_for_thread(
        @current_thread,
        "svcWaitSynchronization(\n  " +
        (objects.map do |obj| obj.inspect end).join(",\n  ") + ")")

      thread = @current_thread
      suspension = LKThread::Suspension.new(thread, "svcWaitSynchronization")
      procs = []
      earlywake = true
      objects.each_with_index.map do |obj, i|
        procs.push(
          [
            obj,
            obj.wait do
              Logger.log_for_thread(thread, "got signal from #{obj}")
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

    def svc_signal_process_wide_key
      condvar = x0
      num_threads_to_wake = x1

      suspensions = @condvar_suspensions.select do |s|
        s.condvar == condvar
      end

      if num_threads_to_wake != -1 then
        suspensions = suspensions[0, num_threads_to_wake]
      end

      suspensions.each do |s|
        s.release do
          x0(0)
        end
      end

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

      x0(0)
      x1(@handle_table.insert(port.client.connect))
    end

    def svc_send_sync_request
      session = @handle_table.get_strict(x0, HIPC::Session::Client)
      message = HIPC::Message.parse(self, @current_thread.tls.addr, 0x100)

      suspension = LKThread::Suspension.new(@current_thread, "svcSendSyncRequest: " + session.describe_message(message))
      session.send_message(message) do |rs|
        suspension.release do
          if rs then
            rs.serialize(self, @current_thread.tls.addr, 0x100)
            x0(0)
          else
            x0(0xf601)
          end
        end
      end
    end
    
    def svc_get_process_id
      x1(@handle_table.get_strict(x1, Process).pid)
      x0(0)
    end

    def svc_get_thread_id
      x1(@handle_table.get_strict(x1, LKThread).tid)
      x0(0)
    end

    def svc_output_debug_string
      Logger.log_for_thread(@current_thread, "DEBUG: " + @mu.mem_read(x0, x1))
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
      when InfoId::TotalMemoryAvailable
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(512 * 1024 * 1024) # TODO: come up with something more believeable
          return        
      when InfoId::TotalMemoryUsage
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(0) # TODO: come up with something more believeable
          return        
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
           InfoId::IdleTickCount
        raise TodoError.new("unimplemented svcGetInfo(#{info_id})")
      when InfoId::RandomEntropy
        if handle != 0 then
          raise ResultError.new(0xe401)
        end
        x1(@random_entropy[info_sub_id])
        return
      end

      if @kernel.environment.target_firmware >= TargetVersion::PK1_200 then
        case info_id
        when InfoId::AddressSpaceBaseAddr
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(object.as_mgr.config.base_addr)
          return
        when InfoId::AddressSpaceSize
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(object.as_mgr.config.end_addr - object.as_mgr.config.base_addr)
          return
        when InfoId::StackRegionBaseAddr
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(object.stack_region.addr)
          return
        when InfoId::StackRegionSize
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(object.stack_region.size)
          return
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
          if handle != 0 then
            raise ResultError.new(0xe401)
          end
          case info_sub_id
          when 0
            x1(@kernel.priveleged_lower_bound)
          when 1
            x1(@kernel.priveleged_upper_bound)
          else
            raise "invalid sub id"
          end
          return
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
        when InfoId::TotalMemoryAvailableWithoutMmHeap
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(512 * 1024 * 1024) # TODO: come up with something more believeable
          return        
        when InfoId::TotalMemoryUsedWithoutMmHeap
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(0) # TODO: come up with something more believeable
          return        
        end
      end

      Logger.log_for_thread(@current_thread, "WARNING: target getting unsupported info #{info_id}")
      x0(0xf001) # let this one past strict error handling
    end

    def svc_accept_session
      server = @handle_table.get_strict(x1, HIPC::Port::Server)
      x1(@handle_table.insert(server.accept))
      x0(0)
    end

    def svc_reply_and_receive
      handles = @mu.mem_read(x1, x2 * 4).unpack("L<*")
      timeout = x4

      if x3 != 0 then
        Logger.log_for_thread(@current_thread, "replying:")
        @mu.mem_read(@current_thread.tls.addr, 0x40).hexdump do |i,h,p|
          Logger.log_for_thread(@current_thread, "  #{i.to_s(16).rjust(8, "0")}  #{h.join(" ")}  |#{p.join}|")
        end
        
        reply_session = @handle_table.get_strict(x3, HIPC::Session::Server)
        reply_session.reply_message(self, HIPC::Message.parse(self, @current_thread.tls.addr, 0x100))
      end
      
      objects = handles.map do |h|
        @handle_table.get_strict(h, [HIPC::Port::Server, HIPC::Session::Server])
      end

      if objects.size == 0 then
        # timeout.
        # not an error, so we don't use ResultError.
        x0(0xea01)
        return
      end

      thread = @current_thread
      suspension = LKThread::Suspension.new(@current_thread, "svcReplyAndReceive")
      procs = []
      earlywake = true
      Logger.log_for_thread(thread, "svcReplyAndReceive:")
      objects.each_with_index.map do |obj, i|
        Logger.log_for_thread(thread, "waiting on #{obj}")
        procs.push(
          [
            obj,
            obj.wait do
              suspension.release do
                x0(0)
                if obj.is_a? HIPC::Session::Server then
                  if obj.closed? then
                    x0(0xf601)
                  else
                    obj.receive_message(self, thread.tls.addr, 0x100)
                    Logger.log_for_thread(thread, "receiving:")
                    @mu.mem_read(thread.tls.addr, 0x40).hexdump do |i,h,p|
                      Logger.log_for_thread(thread, "  #{i.to_s(16).rjust(8, "0")}  #{h.join(" ")}  |#{p.join}|")
                    end
                  end
                end
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

    def svc_create_event
      event = Event.new
      x0(0)
      x1(@handle_table.insert(event.server))
      x2(@handle_table.insert(event.client))
    end
    
    def svc_get_system_info
      info_id = x1
      handle = x2
      info_sub_id = x3

      if @kernel.environment.target_firmware.numeric < TargetVersion::PK1_500 then
        raise "svcGetSystemInfo doesn't exist before 5.0.0"
      end
      
      if handle != 0 then
        raise ResultError.new(0xe401)
      end

      x0(0)

      case info_id
      when SystemInfoId::PrivilegedProcessId
        case info_sub_id
        when 0
            x1(@kernel.priveleged_lower_bound)
        when 1
          x1(@kernel.priveleged_upper_bound)
        else
          raise "invalid sub id"
        end
        return
      else
        raise "unknown system info id: #{info_id}"
      end
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

      port = HIPC::Port.new(name, x2)
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

      port = HIPC::Port.new(name, x2)
      @kernel.named_ports[name] = port
      @kernel.notify_port(name)
      
      x0(0)
      x1(@handle_table.insert(port.server))
    end

    def svc_connect_to_port
      port = @handle_table.get_strict(x1, HIPC::Port::Client)
      x0(0)
      x1(@handle_table.insert(port.connect))
    end
    
    def svc_call_secure_monitor
      smc_sub_id = x0
      smc_args = [x1, x2, x3, x4, x5, x6, x7]
      Logger.log_for_thread(@current_thread, "SMC[0x#{smc_sub_id.to_s(16)}](#{smc_args.inspect})")
      @kernel.secure_monitor.call(self, smc_sub_id, smc_args).each_with_index do |v, i|
        Logger.log_for_thread(@current_thread, "  x#{i} => 0x#{v.to_s(16)}")
        x(i, v)
      end
    end
  end
end
