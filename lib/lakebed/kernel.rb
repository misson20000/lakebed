require_relative "hle/secure_monitor/exosphere.rb"

module Lakebed
  class Scheduler
    def initialize
      @threads = []
    end

    def add_thread(thread)
      @threads.push(thread)
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
  end
  
  class Kernel
    def initialize(environment)
      @environment = environment
      @scheduler = Scheduler.new
      @strict_svcs = false
      @named_ports = Hash.new
      @secure_monitor = HLE::SecureMonitor::Exosphere.new(environment)
      # on <4.0.0, KIPs start at PID 0 I think?
      # on 5.0.0+, KIPs start at PID 1
      @next_pid = 1
      @next_tid = 0x250
      @hle_modules = []

      @port_notifications = []
    end

    attr_reader :environment
    attr_reader :scheduler
    attr_accessor :strict_svcs
    attr_reader :named_ports
    attr_accessor :secure_monitor

    def load_hle_module(mod)
      @hle_modules.push(mod.new(self))
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
          n[:block].call(@named_ports[port])
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
    
    def allocate_pid
      pid = @next_pid
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
      end
    end
  end
end
