require_relative "../hipc.rb"
require_relative "cmif_serialization.rb"

module Lakebed
  module HLE
    module CMIF
      class Server
        def initialize
          @hipc_manager = HipcManager.new(self)
          @deferrals = []
        end

        attr_reader :hipc_manager
        
        def process_deferrals
          deferrals = @deferrals
          @deferrals = []
          @deferrals+= deferrals.filter do |d|
            if d.handle then
              true
            else
              add_session(d.session)
              false
            end
          end
        end
        
        def add_port(port, &block)
          port.wait do
            add_session(Session.new(port.accept, yield))
            add_port(port, &block)
            process_deferrals
          end
        end

        def create_session(object)
          session = HIPC::Session.new
          add_session(Session.new(session.server, object))
          return session.client
        end
        
        def add_session(session)
          session.ko.wait do
            rq = session.ko.receive_message_for_hle
            session.dispatch(self, rq)
            
            add_session(session)
            process_deferrals
          end
        end
      end

      class Request
        def initialize(server, session)
          @server = server
          @session = session
        end

        def describe
          "generic request (override me!)"
        end

        def handle
          raise "abstract"
          nil
        end
        
        attr_reader :server
        attr_reader :session
      end
      
      class SessionCloseRequest < Request
        def describe
          "close session (#{@session.object.class})"
        end

        def handle
          @session.close
          nil
        end
      end
      
      class ObjectCloseRequest < Request
        def initialize(server, session, object, object_id)
          super(server, session)
          @object = object
          @object_id = object_id
        end

        def describe
          "close object #{@object_id} (#{@object.get_object(@object_id).class})"
        end

        def handle
          @object.close_object(@object_id)
          @session.reply(ReserializationContext.new(@server, 0, @object).to_cmif)
          nil
        end
      end

      class CommandRequest < Request
        def initialize(server, session, object, de_ctx, command)
          super(server, session)
          @object = object
          @de_ctx = de_ctx
          @command = command
        end

        def describe
          if @command then
            return "#{@object.class}##{@command.label}{#{@de_ctx.command_id}}(#{@command.describe_args(@de_ctx)})"
          else
            return "unknown command request to #{@object.class}##{@de_ctx.command_id}"
          end
        end

        def handle
          if !@command then
            @session.close
            return nil
          else
            begin
              @session.reply(@command.invoke(@object, @de_ctx))
            rescue DeferralError => e
              return self
              #TODO: rescue DeserializationError => e
              #TODO:  session.close
            end
          end
          return nil
        end
      end
      
      class Session
        def initialize(session, object)
          @ko = session
          @object = object

          @ko.message_describer = self
        end

        def pointer_buffer_size
          512
        end
        
        def parse(server, rq)
          raw_data_offset = (0x10 - rq.raw_data_misalignment) & 0xf
          raw_data = rq.raw_data.byteslice(raw_data_offset, rq.raw_data.bytesize - raw_data_offset)
          case rq.type
          when 2 # Close
            return CloseRequest.new(server, self)
          when 4, 6 # Request, NewRequest
            # TODO: NewRequest
            if @object.is_domain? then
              # TODO: token
              command, in_object_count, data_payload_length, object_id, token = raw_data.unpack("CCS<L<x4L<")
              case command
              when 1 # Send
                object = @object.get_object(object_id)
                de_ctx = DeserializationContext.new(server, rq, raw_data.byteslice(16, raw_data.bytesize - 16), @object)
                return object.parse(server, self, de_ctx)
              when 2 # Close
                return ObjectCloseRequest.new(server, self, @object, object_id)
              else
                raise "unknown domain command: #{command}"
              end
            else
              de_ctx = DeserializationContext.new(server, rq, raw_data, nil)
              return @object.parse(server, self, de_ctx)
            end
          when 5 # Control
            de_ctx = DeserializationContext.new(server, rq, raw_data, nil)
            return server.hipc_manager.parse(server, self, de_ctx)
          else
            raise "unknown request type: #{rq.type}"
          end
        end

        def describe_message(rq)
          parse(nil, rq).describe
        end
        
        def dispatch(server, rq)
          parse(server, rq).handle
        end
        
        def close
          @ko.close
          @object.close
        end

        def reply(cmif_msg)
          @ko.reply_message(nil, cmif_msg.to_hipc)
        end
        
        attr_reader :ko
        attr_accessor :object
      end

      class DeserializationContext
        def initialize(server, rq, raw_data, domain)
          @server = server
          @rq = rq
          @raw_data = raw_data
          @domain = domain

          if raw_data.byteslice(0, 4) != "SFCI" then
            raise "invalid request magic: #{raw_data.byteslice(0, 4)}"
          end

          reset!
        end

        def reset!
          @raw_data_head = 16
        end

        attr_reader :rq
        
        def command_id
          @raw_data.byteslice(8, 4).unpack("L<")[0]
        end

        def pop_raw_data(size, alignment)
          @raw_data_head+= (-@raw_data_head % alignment)
          dat = @raw_data.byteslice(@raw_data_head, size)
          @raw_data_head+= size
          return dat
        end
        
        def prepare_reply(code=0)
          ReserializationContext.new(@server, code, @domain)
        end
      end

      class ReserializationContext
        def initialize(server, code, domain)
          @server = server
          @code = code
          @domain = domain
          @raw_data = String.new
          @pid = nil
          @copy_handles = []
          @move_handles = []
          @out_objects = []
        end

        def to_cmif
          append_raw_data(String.new, 4) # align to word boundary
          Lakebed::CMIF::Message.new(
            0,
            @pid,
            @copy_handles,
            @move_handles,
            raw_data,
            [])
        end
        
        def raw_data
          rd = String.new
          if @domain then
            rd+= [@out_objects.size].pack("L<x12")
          end
          rd+= ["SFCO", @code].pack("a4x4L<x4")
          rd+= @raw_data
          if @domain then
            rd+= @out_objects.map do |o|
              id = @domain.add_object(o)
              puts "sending out object #{o} -> #{id}"
              id
            end.pack("L<*")
          end
          rd
        end

        def append_raw_data(d, alignment)
          @raw_data+= 0.chr * (-@raw_data.bytesize % alignment)
          @raw_data+= d
        end

        def append_move_handle(h)
          @move_handles.push(h)
        end

        def append_copy_handle(h)
          @copy_handles.push(h)
        end

        def append_out_object(o)
          if @domain then
            @out_objects.push(o)
          else
            @move_handles.push(@server.create_session(o))
          end
        end
      end

      class DeferralError < RuntimeError
      end
      
      class Object
        def parse(server, session, de_ctx)
          cmd = self.class.commands[de_ctx.command_id]
          CommandRequest.new(server, session, self, de_ctx, cmd)
        end

        def close
        end
        
        def is_domain?
          false
        end

        class Command
          def initialize(label, serialization, &impl)
            @label = label
            @serialization = serialization
            @impl = impl
          end

          attr_reader :label

          def describe_args(de_ctx)
            de_ctx.reset!
            
            @serialization.filter do |s|
              s.provides_input?
            end.map do |s|
              (s.name || "?") + " = " + s.unpack(de_ctx).inspect
            end.join(", ")
          end
          
          def invoke(object, de_ctx)
            de_ctx.reset!
            
            args = []
            @serialization.each do |s|
              if s.provides_input? then
                args.push(s.unpack(de_ctx))
              end
            end
            
            begin
              rets = object.instance_exec(*args, &@impl)
            rescue ResultError => e
              return de_ctx.prepare_reply(e.code).to_cmif
            end

            if !rets.is_a? Array then
              rets = [rets]
            end
            
            re_ctx = de_ctx.prepare_reply
            @serialization.each do |s|
              if s.provides_output? then
                s.pack(re_ctx, rets.shift)
              end
            end
            
            return re_ctx.to_cmif
          end
        end

        class << self
          def command(id, label, *serialization, &block)
            @commands||= {}
            @commands[id] = Command.new(label, serialization, &block)
          end
          attr_reader :commands
        end
      end

      class DomainObject < Object
        def initialize
          @objects = []
        end

        def is_domain?
          true
        end
        
        def add_object(object)
          id = @objects.size
          @objects.push(object)
          return id
        end

        def get_object(id)
          @objects[id]
        end

        def close_object(id)
          @objects[id].close
          @objects.delete(id)
        end
      end
      
      class HipcManager < Object
        def initialize(server)
          @server = server
        end
        
        command(
          0, # ConvertCurrentObjectToDomain
          Out::RawData.new(4, "L<")) do
          puts "converting to domain"
          domain = DomainObject.new
          old_object = session.object
          session.object = domain
          next domain.add_object(old_object)
        end

        command(
          1, # CopyFromCurrentDomain
          In::RawData.new(4, "L<"),
          Out::Handle.new(:move)) do |object_id|
          puts "copying from domain"
          next @server.create_session(session.object.get_object(object_id))
        end

        command(
          2, # CloneCurrentObject
          Out::Handle.new(:move)) do
          puts "cloning current object"
          next @server.create_session(session.object)
        end

        command(
          3, # QueryPointerBufferSize
          Out::RawData.new(2, "S<")) do
          puts "querying pointer buffer size"
          next session.pointer_buffer_size
        end

        command(
          4, # CloneCurrentObjectEx
          In::RawData.new(4, "L<"),
          Out::Handle.new(:move)) do |_|
          raise "unimplemented"
        end
      end
    end
  end
end
