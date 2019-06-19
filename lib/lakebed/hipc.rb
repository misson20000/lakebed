require_relative "sync.rb"

module Lakebed
  class Port
    def initialize(name, max_sessions)
      @name = name
      @sessions = []
      @max_sessions = max_sessions
      @client = Client.new(self)
      @server = Server.new(self)
      @pending_connections = Queue.new
    end

    def inspect
      "Port(#{@name}, max = #{@max_sessions})"
    end

    attr_accessor :sessions
    attr_reader :max_sessions
    attr_reader :client
    attr_reader :server
    attr_reader :pending_connections
    
    def connect(&proc)
      @pending_connections.push(proc)
      server.signal
    end
    
    class Client < Waitable
      def initialize(port)
        super()
        @port = port
      end

      def is_signaled?
        @port.sessions.length < @port.max_sessions
      end

      def connect(&proc)
        @port.connect(&proc)
      end
    end

    class Server < Waitable
      def initialize(port)
        super()
        @port = port
      end

      def is_signaled?
        !@port.pending_connections.empty?
      end

      def accept
        if @port.pending_connections.empty? then
          raise ResultError.new(0xf201)
        end
        conn = @port.pending_connections.pop
        session = Session.new
        conn.call(session.client)
        session.server
      end
    end
  end

  class Session
    def initialize
      @client = Client.new(self)
      @server = Server.new(self)
      @pending_requests = Queue.new
    end

    def inspect
      "Session"
    end
    
    attr_reader :client
    attr_reader :server
    attr_reader :pending_requests

    class Client
      def initialize(session)
        @session = session
      end
    end

    class Server < Waitable
      def initialize(session)
        super()
        @session = session
      end

      def is_signaled?
        !@session.pending_requests.empty?
      end
    end
  end
end
