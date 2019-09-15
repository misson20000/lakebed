require_relative "logger.rb"

module Lakebed
  class LKThread
    DEFAULT_PARAMS = {
      :gprs => [0] * 31,
      :fprs => [[0, 0]] * 32,
      :priority => 50,
      :processor_id => 3,
      :owns_tls => false,
    }

    GPR_CONSTANTS = 31.times.map do |r|
      UnicornEngine.const_get("UC_ARM64_REG_X" + r.to_s)
    end

    FPR_CONSTANTS = 32.times.map do |r|
      UnicornEngine.const_get("UC_ARM64_REG_V" + r.to_s)
    end

    def initialize(proc, params)
      @process = proc
      @tid = @process.kernel.allocate_tid
      if !params.key?(:entry) then raise "need to specify entry point" end
      if !params.key?(:sp) then raise "need to specify stack pointer" end
      if !params.key?(:tls) then
        tls = @process.as_mgr.alloc_region(@process.sizes[:tls])
        res = @process.as_mgr.alloc_memory_resource(tls.size)
        @process.as_mgr.map_slice!(
          tls.addr,
          res.principal_slice,
          MemoryType::ThreadLocal,
          Perm::RW,
          :label => "TLS",
          :label_base => tls.addr)
        params[:tls] = tls
        params[:owns_tls] = true
      end
      
      params = DEFAULT_PARAMS.merge(params)
      
      @pc = params[:entry]
      @sp = params[:sp]
      @gprs = params[:gprs]
      @fprs = params[:fprs]
      @nzcv = 0
      @priority = params[:priority]
      @processor_id = params[:processor_id]
      @tls = params[:tls]
      @owns_tls = params[:owns_tls]

      @fresh_suspension = Suspension.new(self, "fresh thread")
      @suspension = @fresh_suspension
      @synchronization = nil
      @synchronization_canceled = false
      @current = false
    end

    def to_s
      "#{process.name}::0x#{@tid.to_s(16)}"
    end
    
    class Suspension
      def initialize(thread, description)
        @thread = thread
        @description = description
        @thread.suspend(self)
      end

      attr_reader :thread
      attr_reader :description

      def release(&proc)
        Logger.log_for_thread(@thread, "releasing suspension: #{@description}")
        @thread.resume(self, proc)
      end
    end
    
    attr_reader :process
    attr_reader :tid
    attr_accessor :priority
    attr_accessor :pc
    attr_accessor :gprs
    attr_accessor :fprs
    attr_accessor :nzcv
    attr_accessor :sp
    attr_accessor :synchronization
    attr_accessor :synchronization_canceled
    attr_reader :tls

    def cancel_synchronization
      @synchronization_canceled = true
      if @synchronization then
        Logger.log_for_thread(
          self,
          "cancelled synchronization")
        @synchronization.release do
          @synchronization = nil
          @synchronization_canceled = false
          @process.x0(0xec01)
        end
      end
    end
    
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

      Logger.log_for_thread(self, "committing")
      @sp = @process.mu.reg_read(UnicornEngine::UC_ARM64_REG_SP)
      @gprs = GPR_CONSTANTS.map do |c|
        @process.mu.reg_read(c)
      end
      @fprs = FPR_CONSTANTS.map do |c|
        @process.mu.reg_read(c)
      end
      @nzcv = @process.mu.reg_read(UnicornEngine::UC_ARM64_REG_NZCV)
      @current = false
    end

    def restore
      if @current then
        raise "attempt to restore current thread"
      end
      
      Logger.log_for_thread(self, "restoring")
      @process.mu.reg_write(UnicornEngine::UC_ARM64_REG_SP, @sp)
      @process.mu.reg_write(UnicornEngine::UC_ARM64_REG_TPIDRRO_EL0, @tls.addr)
      @gprs.each_with_index do |r, i|
        @process.mu.reg_write(GPR_CONSTANTS[i], r)
      end
      @fprs.each_with_index do |r, i|
        @process.mu.reg_write(FPR_CONSTANTS[i], r)
      end
      @process.mu.reg_write(UnicornEngine::UC_ARM64_REG_NZCV, @nzcv)
      
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

      Logger.log_for_thread(self, "suspending on #{suspension.description}")
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
        @process.as_mgr.unmap!(@tls.addr, @tls.size)
      end
    end

    def suspended?
      @suspension != nil
    end

    attr_reader :suspension
  end
end
