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

        file.seek(text_segheader[:file_offset])
        text_compressed = file.read(text_compressed_size)

        file.seek(rodata_segheader[:file_offset])
        rodata_compressed = file.read(rodata_compressed_size)

        file.seek(data_segheader[:file_offset])
        data_compressed = file.read(data_compressed_size)

        digest = Digest::SHA2.new(256)
        
        text, rodata, data = [
          text_compressed, rodata_compressed, data_compressed].each_with_index.map do |compressed, i|
          segheader = [text_segheader, rodata_segheader, data_segheader][i]
          if flags[i] then # is compressed
            decompressed = LZ4::Raw::decompress(compressed, segheader[:decompressed_size]).first
          else
            decompressed = compressed
          end
          if flags[i+3] then # check hash
            actual_hash = digest.digest(decompressed)
            if actual_hash != hashes[i] then
              raise "hash mismatch on #{["text", "rodata", "data"][i]} segment (#{actual_hash.unpack("H*").first} != #{hashes[i].unpack("H*").first})"
            end
          end
          if decompressed.bytesize != segheader[:decompressed_size] then
            raise "decompressed size mismatch"
          end
          decompressed
        end

        nso = self.new
        nso.add_segment(text, 5)
        nso.add_segment(rodata, 1)
        nso.add_segment(data + (0.chr * data_segheader[:extra]), 3)
        return nso
      end

      Segment = Struct.new(:content, :permissions)
      
      def add_segment(content, perm)
        target_size = (content.bytesize + 0xfff) & ~0xfff
        content+= 0.chr * (target_size - content.bytesize)

        @segments.push(Segment.new(content, perm))
      end

      def read(offset, size)
        offset = offset.to_i
        text = String.new
        lc = 0
        @segments.each do |seg|
          if lc >= offset + size then
            return text
          end
          if offset - lc < seg.content.bytesize then
            text+= seg.content[offset - lc + text.bytesize, size - text.bytesize]
          end
          lc+= seg.content.bytesize
        end
        return text
      end
      
      attr_reader :segments
    end
  end
end
