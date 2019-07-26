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

        def process_deferrals
          deferrals = @deferrals
          @deferrals = []
          @deferrals+= deferrals.filter do |d|
            if d[:object].dispatch(d[:session], d[:de_ctx]) then
              true
            else
              add_session(d[:session])
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
            raw_data_offset = (0x10 - rq.raw_data_misalignment) & 0xf
            raw_data = rq.raw_data.byteslice(raw_data_offset, rq.raw_data.bytesize - raw_data_offset)
            case rq.type
            when 2 # Close
              session.close
              next
            when 4 # Request
              # TODO: NewRequest
              if session.object.is_domain? then
                # TODO: token
                command, in_object_count, data_payload_length, object_id, token = raw_data.unpack("CCS<L<x4L<")
                case command
                when 1 # Send
                  object = session.object.get_object(object_id)
                  de_ctx = DeserializationContext.new(self, rq, raw_data.byteslice(16, raw_data.bytesize - 16), session.object)
                  if object.dispatch(session, de_ctx) then
                    @deferrals.push({:object => object, :session => session, :de_ctx => de_ctx})
                    next
                  end
                when 2 # Close
                  session.object.close_object(object_id)
                  session.reply(ReserializationContext.new(self, 0, session.object).to_cmif)
                else
                  raise "unknown domain command: #{command}"
                end
              else
                de_ctx = DeserializationContext.new(self, rq, raw_data, nil)
                if session.object.dispatch(session, de_ctx) then
                  @deferrals.push({:object => session.object, :session => session, :de_ctx => de_ctx})
                  next
                end
              end
            when 5 # Control
              de_ctx = DeserializationContext.new(self, rq, raw_data, nil)
              if @hipc_manager.dispatch(session, de_ctx) then
                @deferrals.push({:object => @hipc_manager, :session => session, :de_ctx => de_ctx})
                next
              end
            else
              raise "unknown request type: #{rq.type}"
            end
            add_session(session)
            process_deferrals
          end
        end
      end

      class Session
        def initialize(session, object)
          @ko = session
          @object = object
        end

        def pointer_buffer_size
          512
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
        def dispatch(session, de_ctx)
          @current_session = session
          de_ctx.reset!
          cmd = self.class.commands[de_ctx.command_id]
          if !cmd then
            session.close
          else
            begin
              session.reply(cmd.invoke(self, de_ctx))
            rescue DeferralError => e
              return true
            #TODO: rescue DeserializationError => e
            #TODO:  session.close
            end
          end
          return false
        end

        def close
        end
        
        def session
          @current_session
        end
        
        def is_domain?
          false
        end

        class Command
          def initialize(serialization, &impl)
            @serialization = serialization
            @impl = impl
          end

          def invoke(object, de_ctx)
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
          def command(id, *serialization, &block)
            @commands||= {}
            @commands[id] = Command.new(serialization, &block)
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
