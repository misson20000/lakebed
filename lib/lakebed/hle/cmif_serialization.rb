module Lakebed
  module HLE
    module CMIF
      class In
        def provides_input?
          true
        end

        def provides_output?
          false
        end

        def consumes_return?
          false
        end
        
        attr_reader :name
        
        class RawData < In
          def initialize(size, packing=nil, alignment=size, name=nil)
            @size = size
            @packing = packing
            @alignment = alignment
            @name = name
          end

          def unpack(ctx)
            str = ctx.pop_raw_data(@size, @alignment)
            if @packing then
              return str.unpack(@packing)[0]
            else
              return str
            end
          end
        end

        class Handle < In
          def initialize(mode)
            @mode = mode
          end

          def unpack(ctx)
            if @mode == :move then
              ctx.pop_move_handle
            elsif @mode == :copy then
              ctx.pop_copy_handle
            else
              raise "unknown handle mode: #{@mode}"
            end
          end
        end
        
        class Pid < In
          def initialize
            @name = "pid"
          end

          def unpack(ctx)
            ctx.rq.handle_descriptor[:pid]
          end
        end
      end

      class Buffer
        def initialize(type, name=nil, fixed_size=nil)
          @type = type
          @name = name
          @fixed_size = fixed_size
          
          @in = type[0] == 1
          @out = type[1] == 1
          @hipc_map_alias = type[2] == 1
          @hipc_pointer = type[3] == 1
          @fixed_size = type[4] == 1
          @hipc_auto_select = type[5] == 1
          @hipc_map_transfer_allows_non_secure = type[6] == 1
          @hipc_map_transfer_allows_non_device = type[7] == 1
        end

        attr_reader :name
        
        def provides_input?
          true
        end

        def provides_output?
          true
        end

        def consumes_return?
          @out
        end

        def unpack(ctx)
          if @in && !@out then
            if @hipc_map_alias && !@hipc_pointer && !@hipc_auto_select then
              InputInstance.new(self, ctx.pop_a_descriptor)
            elsif !@hipc_map_alias && @hipc_pointer && !@hipc_auto_select then
              InputInstance.new(self, ctx.pop_x_descriptor)
            else
              raise "unsupported buffer type: 0x" + @type.to_s(16)
            end
          elsif @out && !@in then
            if @hipc_map_alias && !@hipc_pointer && !@hipc_auto_select then
              MapAliasOutputInstance.new(self, ctx.pop_b_descriptor)
            elsif !@hipc_map_alias && @hipc_pointer && !@hipc_auto_select then
              SendOutputInstance.new(self, ctx.next_indexed_buffer)
            else
              raise "unsupported buffer type: 0x" + @type.to_s(16)
            end
          else
            raise "unsupported in/out combination, type: 0x" + @type.to_s(16)
          end
        end

        def pack(ctx, value=nil)
          if !@out then
            return
          end

          if !@hipc_map_alias && @hipc_pointer && !@hipc_auto_select then
            if !value.is_a? SendOutputInstance then
              raise "expected command to return a SendOutputInstance"
            end

            ctx.append_send_buffer(value)
          end
        end
        
        class InputInstance
          def initialize(buffer_spec, descriptor)
            @buffer_spec = buffer_spec
            @descriptor = descriptor
          end

          def inspect
            "Buffer::InputInstance<" + @descriptor.inspect + ">"
          end
          
          def content
            @descriptor.read
          end

          attr_reader :descriptor
        end

        class MapAliasOutputInstance
          def initialize(buffer_spec, descriptor)
            @buffer_spec = buffer_spec
            @descriptor = descriptor
          end

          def inspect
            "Buffer::MapAliasOutputInstance<" + @descriptor.inspect + ">"
          end
          
          def write(data)
            @descriptor.write(data)
          end
        end

        class SendOutputInstance
          def initialize(buffer_spec, index)
            @buffer_spec = buffer_spec
            @index = index
            @value = nil
          end

          def write(data)
            @value = data
          end

          attr_reader :index
          attr_reader :value
        end
      end
      
      class Out
        def provides_input?
          false
        end

        def provides_output?
          true
        end

        def consumes_return?
          true
        end
        
        attr_reader :name
        
        class RawData < Out
          def initialize(size, packing=nil, alignment=size)
            @size = size
            @packing = packing
            @alignment = alignment
          end

          def pack(ctx, value)
            str = @packing ? [value].pack(@packing) : value
            if str.bytesize != @size then
              raise "invalid pack"
            end
            ctx.append_raw_data(str, @alignment)
          end
        end

        class Handle < Out
          def initialize(mode)
            @mode = mode
          end

          def pack(ctx, value)
            if @mode == :move then
              ctx.append_move_handle(value)
            elsif @mode == :copy then
              ctx.append_copy_handle(value)
            else
              raise "unknown handle mode: #{@mode}"
            end
          end
        end

        class Object < Out
          def pack(ctx, value)
            ctx.append_out_object(value)
          end
        end
      end
    end
  end
end
