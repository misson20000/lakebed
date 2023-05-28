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
      @gprs = params[:gprs].clone
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

    class Synchronization < Suspension
      def initialize(thread)
        super(thread, "synchronization")

        @objects = []
        @is_finished = false
      end
      
      def push_object(object, &proc)
        if @is_finished then
          raise "attempt to add object to synchronization that has already finished"
        end
        
        @objects.push(
          :object => object, :proc => object.wait do
            self.finish_synchronization!
            
            self.release do
              proc.call
            end
          end)
      end
      
      def cancel_synchronization!
        self.finish_synchronization!
        
        self.release do
          @thread.process.x0(0xec01)
        end
      end

      def time_out!
        self.finish_synchronization!
        
        self.release do
          @thread.process.x0(0xea01)
        end
      end

      def release(&proc)
        @thread.synchronization = nil
        
        super(&proc)
      end

      def is_finished?
        @is_finished
      end
      
      def finish_synchronization!
        if @is_finished then
          raise "attempt to finish synchronization that has already finished"
        end
        
        Logger.log_for_thread(@thread, "finishing synchronization")

        # cancel all outstanding waits
        @objects.each do |obj|
          obj[:object].unwait(obj[:proc])
        end

        @objects = []
        @is_finished = true
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
      if @synchronization then
        Logger.log_for_thread(
          self,
          "cancelling active synchronization")

        sync = @synchronization
        @synchronization = nil
        
        sync.cancel_synchronization!
      else
        Logger.log_for_thread(
          self,
          "tried to cancel synchronization while not synchronizing")
        @synchronization_canceled = true
      end
    end

    def synchronize(objects, timeout)
      if @synchronization then
        raise "already synchronizing"
      end

      if @suspension then
        raise "already suspended"
      end
      
      suspension = Synchronization::new(self)
      @synchronization = suspension
      
      Logger.log_for_thread(
        self, "synchronizing",
        :timeout => timeout)

      if @synchronization_canceled then
        Logger.log_for_thread(
          self, "  synchronization was already canceled!")

        @synchronization_canceled = false

        suspension.cancel_synchronization!

        return
      end

      if timeout == 0 then
        if objects.size == 0 then
          Logger.log_for_thread(
            self, "  called with instant timeout, no objects, and was not cancelled, so timing out instantly")

          suspension.time_out!

          return
        else
          Logger.log_for_thread(
            self, "  called with instant timeout, so checking objects...")
          
          objects.each_with_index.map do |obj, i|
            if obj.is_signaled? then
              suspension.release do
                yield obj, i
              end
              return
            end
          end
          
          Logger.log_for_thread(
            self, "  no objects were signaled, so timing out immediately")

          suspension.time_out!

          return
        end
      end

      objects.each_with_index do |obj, i|
        Logger.log_for_thread(
          self, "  synchronizing on #{obj}")
        
        suspension.push_object(obj) do
          Logger.log_for_thread(
            self, "  finished synchronizing (object #{obj}, index #{i})")
          yield obj, i
        end

        # if we woke up early, don't keep adding objects
        if suspension.is_finished? then
          Logger.log_for_thread(
            self, "finished synchronizing early, so not waiting on any more objects")
          return
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
