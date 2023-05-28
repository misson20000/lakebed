require "digest"
require "lz4-ruby"

module Lakebed
  module Files
    class Nso
      def initialize
        @segments = []
      end

      def self.from_file(file)
        magic, version, reserved, flags = file.read(0x10).unpack("a4L<L<L<")
        if magic != "NSO0" then
          raise "invalid NSO magic"
        end
        if version != 0 then
          raise "invalid NSO version"
        end

        text_segheader, rodata_segheader, data_segheader = 3.times.map do
          Hash[[:file_offset, :memory_offset, :decompressed_size, :extra].zip(
                 file.read(0x10).unpack("L<L<L<L<"))]
        end

        build_id = file.read(0x20)
        text_compressed_size, rodata_compressed_size, data_compressed_size = file.read(0xc).unpack("L<L<L<")
        file.read(0x1c) # reserved
        file.read(0x18) # irrelevant

        hashes = 3.times.map do
          file.read(0x20)
        end

        if file.pos != 0x100 then
          raise "invalid header size"
        end

        text   = Segment.from_file(file,   text_segheader,   text_compressed_size, flags[0], flags[3] && hashes[0], 5, false)
        rodata = Segment.from_file(file, rodata_segheader, rodata_compressed_size, flags[1], flags[4] && hashes[1], 1, false)
        data   = Segment.from_file(file,   data_segheader,   data_compressed_size, flags[2], flags[5] && hashes[2], 3, true)

        nso = self.new
        nso.add_segment(text)
        nso.add_segment(rodata)
        nso.add_segment(data)
        return nso
      end

      def add_segment(segment)
        @segments.push(segment)
      end

      def read(offset, size)
        offset = offset.to_i
        text = String.new

        @segments.each do |seg|
          if seg.header[:memory_offset] >= offset + size then
            return text
          end
          if offset - seg.header[:memory_offset] < seg.content.bytesize then
            text+= seg.content[offset - seg.header[:memory_offset] + text.bytesize, size - text.bytesize]
          end
        end
        return text
      end

      def write(offset, data)
        @segments.each do |seg|
          if seg.header[:memory_offset] >= offset + data.bytesize then
            return
          end

          if seg.header[:memory_offset] + seg.content.bytesize <= offset then
            next
          end
          
          offset_in_seg = offset - seg.header[:memory_offset]

          data_in_seg = data

          if offset_in_seg < 0 then
            data_in_seg = data_in_seg.byteslice(-offset_in_seg, data_in_seg.bytesize + offset_in_seg)
            offset_in_seg = 0
          end

          data_in_seg = data_in_seg.byteslice(0, seg.content.bytesize - offset_in_seg)

          seg.content = seg.content.byteslice(0, offset_in_seg) + data_in_seg + seg.content.byteslice(offset_in_seg + data_in_seg.bytesize, seg.content.bytesize - offset_in_seg - data_in_seg.bytesize)
        end
      end
      
      def patch_from_ips(ips)
        header = ips.read(5)

        if header == "IPS32" then
          offset_length = 4
        elsif header == "PATCH" then
          offset_length = 3
        else
          raise "invalid IPS magic: " + header
        end

        loop do
          offset_bytes = ips.read(offset_length)

          if offset_bytes == "EOF" || offset_bytes == "EEOF" then
            break
          elsif offset_bytes == nil then
            raise "unexpected EOF in ips file"
          else
            if offset_length == 3 then
              offset = offset_bytes[0] < 16 + offset_bytes[1] << 8 + offset_bytes[2] << 0
            else
              offset = offset_bytes.unpack("L>")[0]
            end
          end

          length = ips.read(2).unpack("S>")[0]

          if length == 0 then
            length = ips.read(2).unpack("S>")[0]
            data = ips.read(1) * length
          else
            data = ips.read(length)
          end

          self.write(offset - 0x40, data)
        end
      end
      
      attr_reader :segments

      class Segment
        def self.from_file(file, header, compressed_size, is_compressed, expected_hash, permissions, includes_bss)
          file.seek(header[:file_offset])
          compressed = file.read(compressed_size)

          if is_compressed then
            decompressed = LZ4::Raw::decompress(compressed, header[:decompressed_size]).first
          else
            decompressed = compressed
          end

          if expected_hash != nil then
            digest = Digest::SHA2.new(256)
            actual_hash = digest.digest(decompressed)

            if actual_hash != expected_hash then
              puts "hash mismatch (#{actual_hash.unpack("H*").first} != #{hashes[i].unpack("H*").first})"              
            end
          end

          if decompressed.bytesize != header[:decompressed_size] then
            raise "decompressed size mismatch"
          end

          if includes_bss then
            decompressed+= 0.chr * header[:extra]
          end

          Segment.new(header, decompressed, permissions)
        end

        def initialize(header, content, permissions)
          @header = header

          rounded_size = (content.bytesize + 0xfff) & ~0xfff
          @content = content + (0.chr * (rounded_size - content.bytesize))
          
          @permissions = permissions
        end

        attr_reader :header
        attr_accessor :content
        attr_reader :permissions
      end
    end
  end
end
