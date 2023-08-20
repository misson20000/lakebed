require_relative "hle/secure_monitor/exosphere.rb"
require_relative "resource_limit.rb"

module Lakebed
  class Scheduler
    def initialize
      @threads = []
      @sleeps = []
    end

    def add_sleep(&proc)
      @sleeps.push(proc)
    end
    
    def add_thread(thread)
      @threads.push(thread)
      
      @threads.sort! do |a, b|
        a.priority <=> b.priority
      end
    end

    def has_next?
      @threads.any? do |t|
        !t.suspended?
      end
    end

    def next_thread
      @threads.find do |t|
        !t.suspended?
      end
    end

    def wake_sleepers
      sleeps = @sleeps
      @sleeps = []

      sleeps.each do |proc|
        proc.call
      end
    end
  end

  class PoolPartition
    def initialize(total)
      @current = 0
      @total = total
    end

    def total_memory_size
      @total
    end

    def current_memory_size
      @current
    end
  end
  
  class Kernel
    def initialize(environment)
      @environment = environment
      @scheduler = Scheduler.new
      @strict_svcs = false
      @named_ports = Hash.new
      @interrupt_events = []
      @secure_monitor = HLE::SecureMonitor::Exosphere.new(environment)
      @pool_partitions = [
        # TODO: pick some better numbers here
        PoolPartition.new(0xCD500000), # Application
        PoolPartition.new(0x1C600000), # Applet
        PoolPartition.new(0x1C600000), # System (got lazy after hunting down applet numbers)
        PoolPartition.new(0x1C600000) # SystemUnsafe
      ]
      @system_resource_limit = ResourceLimit.new
      # on <4.0.0, KIPs start at PID 0 I think?
      # on 5.0.0+, KIPs start at PID 1
      @next_pid = 1
      @next_tid = 0x250
      @processes = {}
      @hle_modules = {}

      @port_notifications = []
    end

    attr_reader :environment
    attr_reader :scheduler
    attr_accessor :strict_svcs
    attr_reader :named_ports
    attr_reader :interrupt_events
    attr_accessor :secure_monitor
    attr_reader :pool_partitions
    attr_reader :system_resource_limit
    attr_reader :processes

    def load_hle_module(mod, *extras)
      @hle_modules[mod] = mod.new(self, *extras)
    end

    def get_hle_module(mod)
      @hle_modules[mod]
    end

    def wait_for_port(port, &block)
      if !@named_ports[port] then
        @port_notifications.push({:port => port, :proc => block})
      else
        yield(@named_ports[port])
      end
    end

    def notify_port(port)
      notifs = @port_notifications
      @port_notifications = []
      @port_notifications+= notifs.filter do |n|
        if n[:port] == port then
          n[:proc].call(@named_ports[port])
          false
        else
          true
        end
      end
    end
    
    def priveleged_lower_bound
      1
    end

    def priveleged_upper_bound
      10
    end
    
    def allocate_pid(proc)
      pid = @next_pid

      @processes[pid] = proc
      
      @next_pid+= 1
      return pid
    end

    def allocate_tid
      tid = @next_tid
      @next_tid+= 1
      return tid
    end

    def kips_loaded
      @next_pid = 0x50
    end
    
    def continue
      while @scheduler.has_next?
        next_thread = @scheduler.next_thread
        if next_thread != @last_thread then
          Logger.log_context_switch(@last_thread, next_thread)
          @last_thread = next_thread
        end
        next_thread.process.continue(next_thread)

        if !@scheduler.has_next? then
          # try to wake some sleepers if we have any, then keep going
          @scheduler.wake_sleepers
        end
      end
    end
  end
end
