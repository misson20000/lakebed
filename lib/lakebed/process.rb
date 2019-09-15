require "unicorn_engine"
require "unicorn_engine/arm64_const"

require_relative "constants.rb"
require_relative "memory.rb"
require_relative "thread.rb"
require_relative "kernel.rb"
require_relative "error.rb"
require_relative "svc.rb"

module Lakebed
  class Process
    BASE_ADDR = 0x71000000
    
    DEFAULT_SIZES = {
      :initial_stack => 8 * 1024 * 1024, # 8 MiB
      :tls => 0x1000, # TLS blocks are actually only 0x200, but this simplifies allocation
    }

    def initialize(kernel, params = {})
      @kernel = kernel
      @pid = kernel.allocate_pid
      @params = params
      @params[:address_space_config]||=
        kernel.environment.target_firmware >= TargetVersion::PK1_200 ?
          Memory::ADDRSPACE_39 : # default to 39-bit addrspace on 2.0.0+
          Memory::ADDRSPACE_36 # default to 36-bit addrspace on 1.0.0
      @sizes = DEFAULT_SIZES.merge(params[:sizes] || {})
      @name = params[:name] || "unnamed_0x#{@pid.to_s(16)}"
      
      # chosen by fair dice roll.
      # guaranteed to be random.
      @random_entropy = [4, 1, 6, 5]
      
      @mu = UnicornEngine::Uc.new(UnicornEngine::UC_ARCH_ARM64, UnicornEngine::UC_MODE_ARM)
      @as_mgr = Memory::AddressSpaceManager.new(self, @params[:address_space_config])
      @handle_table = HandleTable.new(self)
      @threads = []
      @condvar_suspensions = []
      @pool_partition = params[:pool_partition] || kernel.pool_partitions[PoolPartitionId::System]
      @resource_limit = params[:resource_limit] || kernel.system_resource_limit
      @pending_error = nil      
      
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
              svc(iss) # see svc.rb
            else
              raise GuestExceptionError.new(self, "exception (ec: 0b#{ec.to_s(2)}, iss: 0x#{iss.to_s(16)})")
            end
          rescue => e
            if !@kernel.strict_svcs && e.is_a?(ResultError) then
              x0(e.code)
            else
              if !e.is_a? GuestExceptionError then
                # capture backtrace
                e = GuestExceptionError.new(self, "while taking SVC 0x#{iss.to_s(16)}", e)
              end
              @pending_error = e
              @mu.emu_stop
            end
          end

          if @current_thread.suspended? then
            Logger.log_for_thread(@current_thread, "suspended... stopping emulator")
            @mu.emu_stop
          end
        end)

      # add unmapped read hook
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_READ_UNMAPPED, Proc.new do |uc, access, address, size, value|
          @pending_error = UnmappedReadError.new(self, size, address)
          @mu.emu_stop
        end)
      
      # add unmapped write hook
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_WRITE_UNMAPPED, Proc.new do |uc, access, address, size, value|          
          if address == 0x8 && [value].pack("q<").unpack("Q<")[0] == 0xA55AF00DDEADCAFE then
            @pending_error = StratosphereAbortError.new(self)
          else
            @pending_error = InvalidWriteError.new(self, [value].pack("Q<"), address)
          end
          @mu.emu_stop
        end)

      # add protection violation hooks for memory manager
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_READ_PROT, Proc.new do |uc, access, address, size, value|
          if @as_mgr.find_mapping(address).acquire_permissions!(Perm::R) then
            next
          end

          @pending_error = UnmappedReadError.new(self, size, address)
          @mu.emu_stop
        end)
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_FETCH_PROT, Proc.new do |uc, access, address, size, value|
          puts "hit bad fetch at #{address.to_s(16)}"
          if @as_mgr.find_mapping(address).acquire_permissions!(Perm::RX) then
            next
          end

          @pending_error = UnmappedReadError.new(self, size, address)
          @mu.emu_stop
        end)
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_WRITE_PROT, Proc.new do |uc, access, address, size, value|
          if @as_mgr.find_mapping(address).acquire_permissions!(Perm::RW) then
            next
          end

          @pending_error = InvalidWriteError.new(self, [value].pack("Q<"), address)
          @mu.emu_stop
        end)
    end

    class HandleTable
      def initialize(proc)
        @proc = proc
        @handles = Hash.new
        @next_handle = 0xAB000
      end

      def get(handle)
        @handles[handle]
      end

      def get_strict(handle, type, pseudo=true, allow_zero=false)
        if pseudo && handle == 0xffff8001 then
          obj = @proc
        elsif pseudo && handle == 0xffff8000 then
          obj = @proc.current_thread
        elsif handle == 0 && allow_zero then
          obj = nil
        else
          if !@handles.key?(handle) then
            raise ResultError.new(0xe401, "no such handle 0x#{handle.to_s(16)}")
          end
          obj = @handles[handle]
        end

        if type then
          if !type.is_a? Array then
            type = [type]
          end
        
          if !type.any? do |t|
               obj.is_a?(t)
             end then
            raise ResultError.new(0xe401, "accessing handle 0x#{handle.to_s(16)}, expected a #{type}, got #{obj}")
          end
        end
        
        return obj
      end
      
      def insert(obj)
        handle = @next_handle
        @handles[handle] = obj
        @next_handle+= 1
        handle
      end

      def close(handle)
        @handles[handle].close
        @handles.delete(handle)
      end
    end
    
    def start
      stack_resource = @as_mgr.alloc_memory_resource(@sizes[:initial_stack], "initial stack")
      
      @as_mgr.map_slice!(
        @as_mgr.stack_region.addr,
        stack_resource.principal_slice,
        MemoryType::Stack,
        Perm::RW,
        :label => "main thread stack",
        :label_base => @as_mgr.stack_region.addr)
      
      main_thread = LKThread.new(self, :entry => BASE_ADDR, :sp => @as_mgr.stack_region.addr + @sizes[:initial_stack])
      main_thread_handle = @handle_table.insert(main_thread)
      main_thread.start do
        x0(0) # userland exception handling
        x1(main_thread_handle)
      end
      @threads.push(main_thread)
      @kernel.scheduler.add_thread(main_thread)
    end

    attr_reader :kernel
    attr_reader :pid
    attr_reader :params
    attr_reader :sizes
    attr_reader :name
    attr_reader :mu
    attr_reader :as_mgr
    attr_reader :handle_table
    attr_reader :current_thread

    def to_s
      "Process<#{name}, pid 0x#{@pid.to_s(16)}>"
    end
    
    def add_nso(nso)
      addr = BASE_ADDR
      nso.segments.each do |seg|
        if seg.content.bytesize > 0 then
          resource = @as_mgr.wrap_memory_resource(seg.content, "nso segment with #{seg.permissions}")
          @as_mgr.map_slice!(
            addr, resource.principal_slice,
            seg.permissions == Perm::RX ?
              MemoryType::CodeStatic :
              MemoryType::CodeMutable,
            seg.permissions,
            :label => "nso code",
            :label_base => BASE_ADDR
          )
          addr+= seg.content.bytesize
        end
      end
      return nso
    end

    attr_reader :mu
    
    def continue(next_thread)
      if @current_thread != next_thread then
        if @current_thread then
          @current_thread.save
        end
        @current_thread = next_thread
        @current_thread.restore
      end

      @pending_error = nil
      Logger.log_for_thread(next_thread, "starting at #{@current_thread.pc.to_s(16)}")
      @mu.emu_start(@current_thread.pc, 0, 0, 0)
      @current_thread.pc = @mu.reg_read(UnicornEngine::UC_ARM64_REG_PC)
      
      if @pending_error then
        @current_thread.take_exception(@pending_error)
        raise @pending_error
      end
    end

    def x(no, val=nil)
      if val != nil then
        @mu.reg_write(UnicornEngine::UC_ARM64_REG_X0 + no, val)
      else
        @mu.reg_read(UnicornEngine::UC_ARM64_REG_X0 + no)
      end
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
  end
end
