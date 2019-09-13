module Lakebed
  class Waitable
    def initialize
      @waiting_procs = []
    end
    
    def wait(&proc)
      if is_signaled? then
        proc.call
      else
        @waiting_procs.push(proc)
      end
      return proc
    end
    
    def unwait(proc)
      @waiting_procs.delete(proc)
    end
    
    def signal
      if is_signaled? then
        procs = @waiting_procs
        @waiting_procs = []
        procs.each do |p|
          p.call
        end
      end
    end
  end

  class Event
    def initialize
      @server = Server.new(self)
      @client = Client.new(self)
      @is_signaled = false
    end

    def signal
      @is_signaled = true
      @client.signal
    end

    def reset
      @is_signaled = false
    end

    attr_reader :client
    attr_reader :server
    attr_reader :is_signaled
    
    class Server
      def initialize(event)
        @event = event
      end

      def signal
        @event.signal
      end
    end
    
    class Client < Waitable
      def initialize(event)
        @event = event
      end

      def reset
        @event.reset
      end
      
      def is_signaled?
        @event.is_signaled
      end
    end
  end
end
