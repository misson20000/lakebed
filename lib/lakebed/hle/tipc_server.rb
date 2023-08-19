require_relative "../hipc.rb"
require_relative "./cmif_server.rb"

module Lakebed
  module HLE
    module TIPC
      class Object < CMIF::Object
        class << self
          def tipc_command(id, label, &block)
            @tipc_commands||= {}
            @tipc_commands[id] = TipcCommand.new(label, &block)
          end

          attr_reader :tipc_commands
        end

        def parse_tipc(server, session, de_ctx)
          if !self.class.tipc_commands || !self.class.tipc_commands[de_ctx.rq.type - 0x10] then
            raise "unimplemented tipc command #{de_ctx.rq.type - 0x10} on #{self.class.name}"
          end

          cmd = self.class.tipc_commands[de_ctx.rq.type - 0x10]
          TipcCommandRequest.new(server, session, self, de_ctx, cmd)
        end
      end

      class TipcCommand
        def initialize(label, &impl)
          @label = label
          @impl = impl
        end

        attr_reader :label

        def invoke(object, de_ctx, session)
          object.instance_exec(de_ctx, &@impl)
        end
      end

      class TipcCommandRequest < CMIF::CommandRequest
        def describe
          return "tipc request"
        end

        def handle
          if !@command then
            @session.close
            return nil
          else
            begin
              @session.reply_hipc(@command.invoke(@object, @de_ctx, @session))
            rescue ResultError => e
              @session.reply_hipc(HIPC::Message.new(:type => 0x0, :raw_data_misalignemnt => 8, :raw_data => [e.code].pack("L<")))
            rescue DeferralError => e
              return self
            end
          end
          return nil
        end
      end
    end
  end
end
