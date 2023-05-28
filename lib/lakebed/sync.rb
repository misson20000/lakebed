module Lakebed
  class Waitable
    def initialize
      @waiting_procs = []
      @signaling_procs = []
      @is_signaling = false
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
      @signaling_procs.delete(proc)
    end
    
    def signal
      if is_signaled? then
        if @is_signaling then
          @signaling_procs = @signaling_procs.concat(@waiting_procs)
          return
        end
        
        @is_signaling = true
        
        @signaling_procs = @waiting_procs
        @waiting_procs = []

        while !@signaling_procs.empty? do
          @signaling_procs.pop.call
        end

        @is_signaling = false
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

      def close
        @event.signal
      end
    end
    
    class Client < Waitable
      def initialize(event)
        super()
        @event = event
      end

      def reset
        @event.reset
      end
      
      def is_signaled?
        @event.is_signaled
      end

      def close
        
      end
    end
  end
end
