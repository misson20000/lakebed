require_relative "sync.rb"

module Lakebed
  class Port
    def initialize(name, max_sessions)
      @name = name
      @sessions = []
      @max_sessions = max_sessions
      @client = Client.new(self)
      @server = Server.new(self)
    end

    def inspect
      "Port(#{@name}, max = #{@max_sessions})"
    end

    attr_accessor :sessions
    attr_reader :max_sessions
    attr_reader :client
    attr_reader :server
    
    class Client < Waitable
      def initialize(port)
        super()
        @port = port
      end

      def is_signaled?
        @port.sessions.length < @port.max_sessions
      end
    end

    class Server < Waitable
      def initialize(port)
        super()
        @port = port
      end

      def is_signaled?
        false
      end
    end
  end
end
