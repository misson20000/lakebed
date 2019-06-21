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
      @next_pid = 0x50
      @next_tid = 0x250
    end

    attr_reader :environment
    attr_reader :scheduler
    attr_accessor :strict_svcs
    attr_reader :named_ports
    attr_accessor :secure_monitor

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
    
    def continue
      while @scheduler.has_next?
        next_thread = @scheduler.next_thread
        next_thread.process.continue(next_thread)
      end
    end
  end
end
