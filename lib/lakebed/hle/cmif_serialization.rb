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
          
          @in = type[0]
          @out = type[1]
          @hipc_map_alias = type[2]
          @hipc_pointer = type[3]
          @fixed_size = type[4]
          @hipc_auto_select = type[5]
          @hipc_map_transfer_allows_non_secure = type[6]
          @hipc_map_transfer_allows_non_device = type[7]
        end

        attr_reader :name
        
        def provides_input?
          true
        end

        def provides_output?
          false
        end

        def unpack(ctx)
          if @type == 0x19 then
            descriptor = ctx.pop_x_descriptor

            Instance.new(self, descriptor)
          else
            raise "unsupported buffer type"
          end
        end

        class Instance
          def initialize(buffer_spec, descriptor)
            @buffer_spec = buffer_spec
            @descriptor = descriptor
          end

          def inspect
            "Buffer::Instance<" + @descriptor.inspect + ">"
          end
          
          def content
            @descriptor.read
          end
        end
      end
      
      class Out
        def provides_input?
          false
        end

        def provides_output?
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
