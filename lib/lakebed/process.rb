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
      :heap_region => 64 * 1024 * 1024, # 64 MiB
      :stack => 8 * 1024 * 1024, # 8 MiB
      :tls => 0x1000, # TLS blocks are actually only 0x200, but this simplifies allocation
      :alias_region => 0x20000, # arbitrary
      :stack_region => 0x80000000,
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
      
      # chosen by fair dice roll.
      # guaranteed to be random.
      @random_entropy = [4, 1, 6, 5]
      
      @mu = UnicornEngine::Uc.new(UnicornEngine::UC_ARCH_ARM64, UnicornEngine::UC_MODE_ARM)
      @as_mgr = Memory::AddressSpaceManager.new(@params[:address_space_config])
      @handle_table = HandleTable.new(self)
      @threads = []
      @condvar_suspensions = []
      
      @alias_region = @as_mgr.alloc(
        @sizes[:alias_region],
        :label => "alias region",
        :memory_type => MemoryType::Reserved,
        :permission => Perm::None)

      @heap_region = @as_mgr.alloc(
        @sizes[:heap_region],
        :label => "heap region",
        :memory_type => MemoryType::Reserved,
        :permission => Perm::None)

      @stack_region = @as_mgr.alloc(
        @as_mgr.config.stack_region_size,
        :label => "stack region",
        :memory_type => MemoryType::Reserved,
        :permission => Perm::None)

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
            puts "thread has been suspended..."
            @mu.emu_stop
          end
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

      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_WRITE_PROT, Proc.new do |uc, access, address, size, value|
          @pending_error = InvalidWriteError.new(self, [value].pack("Q<"), address)
          @mu.emu_stop
        end)

      # add unmapped read hook
      @mu.hook_add(
        UnicornEngine::UC_HOOK_MEM_READ_UNMAPPED, Proc.new do |uc, access, address, size, value|
          @pending_error = UnmappedReadError.new(self, size, address)
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
      stack_alloc = @as_mgr.alloc(
        @sizes[:stack],
        :label => "main thread stack",
        :memory_type => MemoryType::Stack,
        :permission => Perm::RW)
      stack_alloc.map(@mu)
      main_thread = LKThread.new(self, :entry => BASE_ADDR, :sp => stack_alloc.addr + stack_alloc.size)
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
    attr_reader :mu
    attr_reader :as_mgr
    attr_reader :handle_table
    attr_reader :current_thread

    attr_reader :alias_region
    attr_reader :heap_region
    attr_reader :stack_region
        
    def add_nso(nso)
      addr = BASE_ADDR
      nso.segments.each do |seg|
        if seg.content.bytesize > 0 then
          alloc = @as_mgr.force(
            addr, seg.content.bytesize, {
              :label => "nso code",
              :memory_type => seg.permissions == Perm::RX ?
                                MemoryType::CodeStatic :
                                MemoryType::CodeMutable,
              :permission => seg.permissions
            })
          @mu.mem_map(alloc.addr, alloc.size)
          @mu.mem_write(alloc.addr, seg.content)
          @mu.mem_protect(alloc.addr, alloc.size, seg.permissions)
          addr+= alloc.size
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
      puts "starting at #{@current_thread.pc.to_s(16)}"
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
