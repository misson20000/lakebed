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
        
        class RawData < In
          def initialize(size, packing=nil, alignment=size)
            @size = size
            @packing = packing
            @alignment = alignment
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
          end

          def unpack(ctx)
            ctx.rq.handle_descriptor[:pid]
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
