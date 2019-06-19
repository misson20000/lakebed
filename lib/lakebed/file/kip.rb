require "pry"

module Lakebed
  module Files
    class Kip
      def self.blz_decompress(blob, dec_size)
        # based on hactool
        if blob.bytesize == 0 then
          return 0.chr * dec_size
        end
        
        cmp_and_hdr_size, header_size, addl_size = blob.byteslice(-12, 12).unpack("L<L<L<")

        cmp_start = blob.bytesize - cmp_and_hdr_size
        cmp_ofs = cmp_and_hdr_size - header_size
        out_ofs = cmp_and_hdr_size + addl_size

        blob+= 0.chr * (dec_size - blob.bytesize)
        
        while out_ofs > 0 do
          cmp_ofs-= 1
          control = blob.getbyte(cmp_start + cmp_ofs)
          8.times do |bit|
            if (control & (0x80 >> bit)) != 0 then
              if cmp_ofs < 2 then
                raise "kip1 decompression out of bounds"
              end
              cmp_ofs-= 2
              seg_val = blob.byteslice(cmp_start + cmp_ofs, 2).unpack("S<")[0]
              seg_size = ((seg_val >> 12) & 0xf) + 3
              seg_ofs = (seg_val & 0x0fff) + 3
              if out_ofs < seg_size
                seg_size = out_ofs
              end
              out_ofs-= seg_size

              seg_size.times do |j|
                blob.setbyte(cmp_start + out_ofs + j, blob.getbyte(cmp_start + out_ofs + j + seg_ofs))
              end
            else
              if cmp_ofs < 1 then
                raise "kip1 decompression out of bounds"
              end
              out_ofs-= 1
              cmp_ofs-= 1
              blob.setbyte(cmp_start + out_ofs, blob.getbyte(cmp_start + cmp_ofs))
            end
            if out_ofs == 0 then
              return blob
            end
          end
        end
        return blob
      end
      
      def self.from_file(file)
        magic, name, tid, category, prio, core, flags = file.read(0x20).unpack("a4Z12Q<L<CCxC")
        if magic != "KIP1" then
          raise "invalid KIP magic"
        end

        text, rodata, data, bss, _, _ = 6.times.map do
          Hash[[:out_offset, :decompressed_size, :compressed_size, :attribute].zip(
                 file.read(0x10).unpack("L<L<L<L<"))]
        end

        kernel_caps = file.read(0x80)
        offset = 0
        contents = [text, rodata, data, bss].each_with_index.map do |seg, i|
          content = file.read(seg[:compressed_size])
          if flags[i] == 1 then # compressed
            content = blz_decompress(content, seg[:decompressed_size])
          end

          if seg[:decompressed_size] != content.bytesize then
            raise "size mismatch"
          end

          if seg[:out_offset] != offset then
            raise "offset mismatch"
          end

          target_size = (content.bytesize + 0xfff) & ~0xfff
          content+= 0.chr * (target_size - content.bytesize)
          offset+= target_size

          content
        end

        kip = self.new
        kip.add_segment(contents[0], 5) # text
        kip.add_segment(contents[1], 1) # rodata
        kip.add_segment(contents[2], 3) # data
        kip.add_segment(contents[3], 3) # bss
        return kip
      end

      Segment = Struct.new(:content, :permissions)

      def initialize
        @segments = []
      end
      
      def add_segment(content, perm)
        @segments.push(Segment.new(content, perm))
      end

      attr_reader :segments
    end
  end
end
