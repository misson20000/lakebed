module Lakebed
  class LKThread
    DEFAULT_PARAMS = {
      :gprs => [0] * 31,
      :priority => 50,
      :processor_id => 3,
      :owns_tls => false,
    }
    
    def initialize(proc, params)
      @process = proc
      @tid = @process.kernel.allocate_tid
      if !params.key?(:entry) then raise "need to specify entry point" end
      if !params.key?(:sp) then raise "need to specify stack pointer" end
      if !params.key?(:tls) then
        tls = @process.as_mgr.alloc(
          @process.sizes[:tls],
          :label => "TLS",
          :memory_type => MemoryType::ThreadLocal,
          :permission => Perm::RW)
        tls.map(@process.mu)
        params[:tls] = tls
        params[:owns_tls] = true
      end
      
      params = DEFAULT_PARAMS.merge(params)
      
      @pc = params[:entry]
      @gprs = params[:gprs]
      @sp = params[:sp]
      @priority = params[:priority]
      @processor_id = params[:processor_id]
      @tls = params[:tls]
      @owns_tls = params[:owns_tls]

      @fresh_suspension = Suspension.new(self, "fresh thread")
      @suspension = @fresh_suspension
      @current = false
    end

    class Suspension
      def initialize(thread, description)
        @thread = thread
        @description = description
        @thread.suspend(self)
      end

      attr_reader :description

      def release(&proc)
        @thread.resume(self, proc)
      end
    end
    
    attr_reader :process
    attr_reader :tid
    attr_reader :priority
    attr_accessor :pc
    attr_reader :tls
    
    def start
      if @suspension != @fresh_suspension || @fresh_suspension == nil then
        raise "cannot start a non-fresh thread"
      end
      @fresh_suspension.release do
        yield
      end
      @fresh_suspension = nil
    end

    def save
      if !@current then
        raise "attempt to commit non-current thread"
      end
      
      puts "committing thread"
      @sp = @process.mu.reg_read(UnicornEngine::UC_ARM64_REG_SP)
      @current = false
    end

    def restore
      if @current then
        raise "attempt to restore current thread"
      end
      
      puts "restoring thread"
      @process.mu.reg_write(UnicornEngine::UC_ARM64_REG_SP, @sp)
      @process.mu.reg_write(UnicornEngine::UC_ARM64_REG_TPIDRRO_EL0, @tls.addr)

      @current = true
      
      if @restore_proc != nil
        @restore_proc.call
        @restore_proc = nil
      end
    end

    def suspend(suspension)
      if @suspension then
        raise "attempt to double-suspend thread (current: #{@suspension.description}, attempted: #{desc})"
      end

      puts "suspending (#{suspension.description})"
      @suspension = suspension
      @active = false
      @status = :suspended
      @suspension
    end

    def resume(sus, proc)
      if sus != @suspension then
        raise "attempt to resume thread with bad suspension"
      end
      @suspension = nil

      if @current then
        proc.call
      else
        if @restore_proc != nil then
          raise "invalid state"
        end
        @restore_proc = proc
      end
    end
    
    def take_exception(e)
      @active = false
      @status = :exception
      @exception = e
    end
    
    def destroy
      if @owns_tls then
        @tls.unmap(@proc.mu)
      end
    end

    def suspended?
      @suspension != nil
    end

    attr_reader :suspension
  end
end
