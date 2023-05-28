require "hexdump"
require_relative "error.rb"
require_relative "sync.rb"
require_relative "hipc.rb"

module Lakebed
  class Process
    def svc(id)
      case id
      when 0x1
        svc_set_heap_size
      when 0x4
        svc_map_memory
      when 0x5
        svc_unmap_memory
      when 0x6
        svc_query_memory
      when 0x8
        svc_create_thread
      when 0x9
        svc_start_thread
      when 0xb
        svc_sleep_thread
      when 0xc
        svc_get_thread_priority
      when 0xd
        svc_set_thread_priority
      when 0x11
        svc_signal_event
      when 0x13
        svc_map_shared_memory
      when 0x15
        svc_create_transfer_memory
      when 0x16
        svc_close_handle
      when 0x18
        svc_wait_synchronization
      when 0x19
        svc_cancel_synchronization
      when 0x1a
        svc_arbitrate_lock
      when 0x1b
        svc_arbitrate_unlock
      when 0x1c
        svc_wait_process_wide_key_atomic
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
      when 0x30
        svc_get_resource_limit_limit_value
      when 0x31
        svc_get_resource_limit_current_value
      when 0x40
        svc_create_session
      when 0x41
        svc_accept_session
      when 0x43
        svc_reply_and_receive
      when 0x45
        svc_create_event
      when 0x53
        svc_create_interrupt_event
      when 0x65
        svc_get_process_list
      when 0x6f
        svc_get_system_info
      when 0x70
        svc_create_port
      when 0x71
        svc_manage_named_port
      when 0x72
        svc_connect_to_port
      when 0x7d
        svc_create_resource_limit
      when 0x7e
        svc_set_resource_limit_limit_value
      when 0x7f
        svc_call_secure_monitor
      else
        raise UnknownSvcError.new(self, id)
      end
    end

    def svc_set_heap_size
      size = x1
      
      if size > @as_mgr.heap_region.size then
        raise "attempted to set heap too large"
      end

      if size & 0xfff != 0 then
        raise "attempted to set bad heap size"
      end

      if @heap_resource then
        raise "TODO: implement resizing heap"
      end

      @heap_resource = @as_mgr.alloc_memory_resource(size, "heap")
      
      @as_mgr.map_slice!(
        @as_mgr.heap_region.addr,
        @heap_resource.principal_slice,
        MemoryType::Heap,
        Perm::RW,
        :label => "heap",
        :label_base => @as_mgr.heap_region.addr)

      Logger.log_for_thread(@current_thread, "resized heap", :size => size.to_s(16), :addr => @as_mgr.heap_region.addr.to_s(16))
      
      x0(0)
      x1(@as_mgr.heap_region.addr)
    end
    
    def svc_map_memory
      dst_addr = x0
      src_addr = x1
      size = x2

      if !@as_mgr.stack_region.encloses_region?(dst_addr, size) then
        raise ResultError.new(0xdc01)
      end

      puts "SVCMAPMEMORY: 0x#{src_addr.to_s(16)} -> 0x#{dst_addr.to_s(16)}, +0x#{size.to_s(16)}"
      @as_mgr.reprotect!(src_addr, size, 0)
      puts "Reprotected old region..."
      @as_mgr.dump_mappings
      puts "Mirroring in new region..."
      @as_mgr.mirror!(@as_mgr, src_addr, dst_addr, size, MemoryType::Stack, 3)

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

      puts "SVCUNMAPMEMORY: 0x#{src_addr.to_s(16)} -> 0x#{dst_addr.to_s(16)}, +0x#{size.to_s(16)}"
      
      if !Memory::addr_aligned?(dst_addr) || !Memory::addr_aligned?(src_addr) then
        raise ResultError.new(0xcc01)
      end

      if size == 0 || !Memory::size_aligned?(size) then
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

      if !@as_mgr.stack_region.encloses_region?(dst_addr, size) then
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

      mapping = @as_mgr.find_mapping(addr)
      puts "query memory 0x#{addr.to_s(16)}: #{mapping}"
      @mu.mem_write(meminfo, [
                      mapping.addr,
                      mapping.size,
                      mapping.type,
                      0,
                      mapping.permissions || 0,
                      0, 0, 0
                    ].pack("Q<Q<L<L<L<L<L<L<"))
      
      x0(0)
      x1(0)
    end

    def svc_create_thread
      entry = x1
      context = x2.to_i
      sp = x3
      prio = x4
      
      thread = LKThread.new(self, {:entry => entry, :sp => sp})
      thread.gprs[0] = context # context
      thread.priority = prio

      # x5: processor id is ignored

      @threads.push(thread)
      @kernel.scheduler.add_thread(thread)

      x0(0)
      x1(@handle_table.insert(thread))
    end

    def svc_start_thread
      thread = @handle_table.get_strict(x0, LKThread)
      thread.start do
        Logger.log_for_thread(thread, "thread is being scheduled for the first time. x0: 0x" + x0.to_s(16))
        # thread context is already preloaded
      end
      x0(0)
    end
    
    def svc_sleep_thread
      thread = @current_thread
      
      Logger.log_for_thread(thread, "sleep #{x0}")

      suspension = LKThread::Suspension.new(thread, "sleep")
      
      @kernel.scheduler.add_sleep do
        suspension.release do
          Logger.log_for_thread(thread, "woke from sleep")
        end
      end
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

    def svc_signal_event
      event = @handle_table.get_strict(x0, Event::Server)
      event.signal
      x0(0)
    end

    def svc_map_shared_memory
      resource = @handle_table.get_strict(x0, Memory::MemoryResource)
      addr = x1
      size = x2
      perm = x3

      # TODO: restrict mapping shared memory to certain portions of address space

      puts "SVCMAPSHAREDMEMORY: #{resource.label} -> 0x#{addr.to_s(16)}, +0x#{size.to_s(16)}"
      @as_mgr.map_slice!(addr, resource.principal_slice, MemoryType::SharedMemory, perm, {})

      x0(0)
    end

    def svc_create_transfer_memory
      addr = x1
      size = x2
      perm = x3

      x0(0)
      x1(@handle_table.insert(Memory::TransferMemory.new))
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

      thread = @current_thread
      thread.synchronize(objects, timeout) do |obj, i|
        x0(0)
        x1(i)
      end
    end
    
    def svc_cancel_synchronization
      if x0 == 0 then
        # libstratosphere does this sometimes...
        # TODO: convince SciresM to fix this
        raise "does libstratosphere still do this?"
        x0(0xe401)
        return
      end
      
      thread = @handle_table.get_strict(x0, LKThread)
      Logger.log_for_thread(@current_thread, "svcCancelSynchronization(thread 0x#{thread.tid.to_s(16)})")
      thread.cancel_synchronization
      x0(0)
    end

    def svc_arbitrate_lock
      thread_handle = x0
      addr = x1
      tag = x2

      wait_for_address(thread_handle, addr, tag)

      x0(0)
    end

    def svc_arbitrate_unlock
      addr = x0

      signal_to_address(addr)

      x0(0)
    end
    
    def svc_wait_process_wide_key_atomic
      address = x0
      cv_key = x1
      tag = x2
      timeout_ns = x3

      wait_condition_variable(address, cv_key, tag, timeout_ns)
    end
    
    def svc_signal_process_wide_key
      cv_key = x0
      count = x1

      signal_condition_variable(cv_key, count)
      
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
      buffer_receiver = message.strip_buffer_receiver!

      suspension = LKThread::Suspension.new(@current_thread, "svcSendSyncRequest: " + session.describe_message(message) + " to " + session.session.server.to_s)
      begin
        session.send_message(message) do |rs|
          suspension.release do
            if rs then
              rs.serialize(self, @current_thread.tls.addr, 0x100, buffer_receiver)
              x0(0)
            else
              x0(0xf601)
            end
          end
        end
      rescue => e
        Logger.log_for_thread(@current_thread, "encountered exception during svcSendSyncRequest:")
        @mu.mem_read(@current_thread.tls.addr, 0x40).hexdump do |i,h,p|
          Logger.log_for_thread(@current_thread, "    #{i.to_s(16).rjust(8, "0")}  #{h.join(" ")}  |#{p.join}|")
        end
        raise e
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
        x1(object.as_mgr.alias_region.addr)
        return
      when InfoId::AliasRegionSize
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.as_mgr.alias_region.size)
        return
      when InfoId::HeapRegionBaseAddr
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.as_mgr.heap_region.addr)
        return
      when InfoId::HeapRegionSize
        if !object.is_a?(Process) then
          raise ResultError.new(0xe401)
        end
        if info_sub_id != 0 then
          raise ResultError.new(0xf001)
        end
        x1(object.as_mgr.heap_region.size)
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
      when InfoId::ResourceLimitHandle
        x1(@handle_table.insert(@resource_limit))
        return
      when InfoId::IdleTickCount
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
          x1(object.as_mgr.stack_region.addr)
          return
        when InfoId::StackRegionSize
          if !object.is_a?(Process) then
            raise ResultError.new(0xe401)
          end
          x1(object.as_mgr.stack_region.size)
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

    def svc_get_resource_limit_limit_value
      rl = @handle_table.get_strict(x1, ResourceLimit)
      x1(rl.get_limit_value(x2))
      x0(0)
    end

    def svc_get_resource_limit_current_value
      rl = @handle_table.get_strict(x1, ResourceLimit)
      x1(rl.get_current_value(x2))
      x0(0)
    end

    def svc_accept_session
      server = @handle_table.get_strict(x1, HIPC::Port::Server)
      session = server.accept
      
      Logger.log_for_thread(@current_thread, "svcAcceptSession", :server => server, :session => session)
      
      x1(@handle_table.insert(session))
      x0(0)
    end

    def svc_create_session
      is_light = x2
      name = x3

      session = HIPC::Session.new()

      x0(0)
      x1(@handle_table.insert(session.server))
      x2(@handle_table.insert(session.client))
    end
    
    def svc_reply_and_receive
      handles = @mu.mem_read(x1, x2 * 4).unpack("L<*")
      timeout = x4

      reply_to_handle = x3 & 0xffffffff

      Logger.log_for_thread(@current_thread, "svcReplyAndReceive", :timeout => timeout, :reply_to_handle => reply_to_handle)
      
      Logger.log_for_thread(@current_thread, "  replying: (handle (w3): 0x#{reply_to_handle.to_s(16)})")
      @mu.mem_read(@current_thread.tls.addr, 0x40).hexdump do |i,h,p|
        Logger.log_for_thread(@current_thread, "    #{i.to_s(16).rjust(8, "0")}  #{h.join(" ")}  |#{p.join}|")
      end

      reply_message = HIPC::Message.parse(self, @current_thread.tls.addr, 0x100)
      buffer_receiver = reply_message.strip_buffer_receiver!
      
      if reply_to_handle != 0 then
        reply_session = @handle_table.get_strict(reply_to_handle, HIPC::Session::Server)
        reply_session.reply_message(self, reply_message)
      end
      
      objects = handles.map do |h|
        @handle_table.get_strict(h, [HIPC::Port::Server, HIPC::Session::Server])
      end

      thread = @current_thread
      thread.synchronize(objects, timeout) do |obj, i|
        x0(0)
        if obj.is_a? HIPC::Session::Server then
          if obj.closed? then
            x0(0xf601)
          else
            obj.receive_message_into(self, thread.tls.addr, 0x100, buffer_receiver)
            Logger.log_for_thread(thread, "receiving:")
            @mu.mem_read(thread.tls.addr, 0x40).hexdump do |i,h,p|
              Logger.log_for_thread(thread, "  #{i.to_s(16).rjust(8, "0")}  #{h.join(" ")}  |#{p.join}|")
            end
          end
        end
        x1(i)
      end
    end

    def svc_create_event
      event = Event.new
      x0(0)
      x1(@handle_table.insert(event.server))
      x2(@handle_table.insert(event.client))
    end

    def svc_create_interrupt_event
      irq = x1
      type = x2

      event = Event.new
      x0(0)
      x1(@handle_table.insert(event.client))

      Logger.log_for_thread(@current_thread, "created interrupt event", :irq => irq, :type => type, :event => event)
      
      @kernel.interrupt_events[irq] = event
    end

    def svc_get_process_list
      buffer = x1
      buffer_size = x2

      pids = @kernel.processes.each_pair.map do |pair|
        pair[0]
      end

      @mu.mem_write(buffer, pids.pack("Q<*").byteslice(0, buffer_size))
      
      x0(0)
      x1(pids.size)
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
      when SystemInfoId::TotalMemorySize
        x1(@kernel.pool_partitions[info_sub_id].total_memory_size)
      when SystemInfoId::CurrentMemorySize
        x1(@kernel.pool_partitions[info_sub_id].current_memory_size)
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

    def svc_create_resource_limit
      x0(0)
      x1(@handle_table.insert(ResourceLimit.new))
    end

    def svc_set_resource_limit_limit_value
      rl = @handle_table.get_strict(x0, ResourceLimit)
      rl.set_limit_value(x1, x2)
      x0(0)
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

    CondvarSuspension = Struct.new(:addr, :key, :tag, :suspension)
    MutexSuspension = Struct.new(:addr, :tag, :suspension)
    HandleWaitMask = 0x40000000

    def wait_condition_variable(addr, key, value, timeout)
      suspensions = @mutex_suspensions.select do |s|
        s.addr == addr
      end
      
      next_owner = suspensions.pop
      has_waiters = !suspensions.empty?
      next_owner_value = 0
      
      if next_owner != nil then
        next_owner_value = next_owner.tag

        if has_waiters then
          next_owner_value|= HandleWaitMask
        end

        @mutex_suspensions.delete(next_owner)
        
        next_owner.suspension.release do
          x0(0)
        end
      end

      @mu.mem_write(key, [1].pack("L<"))
      @mu.mem_write(addr, [next_owner_value].pack("L<"))
      
      if timeout == 0 then
        x0(0xea01) # timed out
        return
      end
      
      suspension = LKThread::Suspension.new(@current_thread, "svcWaitProcessWideKeyAtomic(addr 0x#{addr.to_s(16)}, key 0x#{key.to_s(16)}, value 0x#{value.to_s(16)}, timeout #{timeout})")
      @condvar_suspensions.push(CondvarSuspension.new(addr, key, value, suspension))
    end

    def signal_condition_variable(key, count)
      #Logger.log_for_thread(@current_thread, "svcSignalProcessWideKey(0x#{key.to_s(16)})")
      
      suspensions = []
      has_waiters = false

      # figure out which suspensions to release
      @condvar_suspensions.delete_if do |cvs|
        if cvs.key == key then
          if suspensions.size < count then
            suspensions.push(cvs)
            true
          else
            has_waiters = true
          end
        end
        
        false
      end

      # try to lock the mutex on behalf of each thread we're waking, sending them off to the mutex arbitrator
      suspensions.each do |s|
        prev_tag = update_lock_atomic(s.addr, s.value, HandleWaitMask)

        if prev_tag == 0 then
          s.suspension.release do
            x0(0)
          end
        else
          @mutex_suspensions.push(MutexSuspension.new(s.addr, s.value, s.suspension))
        end
      end
      
      if !has_waiters then
        @mu.mem_write(key, [0].pack("L<"))
      end
    end

    def update_lock_atomic(address, if_zero, new_orr_mask)
      value = @mu.mem_read(address, 4).unpack("L<")

      if value == 0 then
        new_value = if_zero
      else
        new_value = value | new_orr_mask
      end

      @mu.mem_write(address, [new_value].pack("L<"))

      value
    end
    
    def wait_for_address(handle, addr, tag)
      test_tag = @mu.mem_read(addr, 4).unpack("L<")[0]

      # if mutex is not held by the thread userspace thinks it is...
      if test_tag != (handle | HandleWaitMask) then
        return
      end

      thread = @handle_table.get_strict(handle, LKThread)

      # suspend the current thread
      suspension = LKThread::Suspension.new(@current_thread, "lock mutex(0x#{addr.to_s(16)})")
      @mutex_suspensions.push(MutexSuspension.new(addr, tag, suspension))
    end

    def signal_to_address(address)
      next_owner = nil
      has_waiters = false

      # figure out the next owner
      @mutex_suspensions.delete_if do |mxs|
        if mxs.addr == address then
          if next_owner == nil then
            next_owner = mxs
            true
          else
            has_waiters = true
            false
          end
        else
          false
        end
      end

      # figure out what to write to the mutex
      next_value = 0
      if next_owner != nil then
        next_value = next_owner.tag

        if has_waiters
          next_value|= HandleWaitMask
        end
      end

      # write it to the mutex
      @mu.mem_write(address, [next_value].pack("L<"))

      # if we decided on another owner, wake it up
      if next_owner != nil then
        next_owner.suspension.release do
          x0(0)
        end
      end
    end
  end
end
