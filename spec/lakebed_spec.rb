require "lakebed"

RSpec.describe Lakebed do
  it "has a version number" do
    expect(Lakebed::VERSION).not_to be nil
  end

  describe Lakebed::Nso do
    describe "#each_segment" do
      it "iterates over segments added by #add_segment" do
        nso = Lakebed::Nso.new
        seg = "abc" + (0.chr * (0x1000 - 3))
        nso.add_segment(seg, 3)
        expect { |b| nso.each_segment(&b) }.to yield_with_args(seg, 3)
      end
    end

    describe "#read" do
      it "reads across segments" do
        nso = Lakebed::Nso.new
        seg1 = "abc" + ("d" * (0x1000 - 3))
        seg2 = "efg" + ("h" * (0x1000 - 3))
        nso.add_segment(seg1, 3)
        nso.add_segment(seg2, 3)
        expect(nso.read(0x1000 - 3, 6)).to eq("dddefg")
      end
    end
  end
  
  describe Lakebed::NsoBuilder do
    describe "#add_section" do
      it "returns a section" do
        builder = Lakebed::NsoBuilder.new
        expect(builder.add_section("abc", :text)).to be_a(Lakebed::NsoBuilder::Section)
      end
    end

    describe Lakebed::NsoBuilder::Relocation do
      describe "#run" do
        {"R_AARCH64_ABS64" => [128 + 8].pack("Q<"),
         "R_AARCH64_ABS32" => [128 + 8].pack("L<"),
         "R_AARCH64_ABS16" => [128 + 8].pack("S<"),
         "R_AARCH64_PREL64" => [128 + 8 - 12].pack("Q<"),
         "R_AARCH64_PREL32" => [128 + 8 - 12].pack("L<"),
         "R_AARCH64_PREL16" => [128 + 8 - 12].pack("S<")}.each_pair do |rel, expected_value|
          describe "#{rel}" do
            it "works" do
              loc = instance_double("Lakebed::NsoBuilder::Location", :to_i => 12)
              symbols = {
                "test_symbol" => instance_double("Lakebed::NsoBuilder::Location", :to_i => 128)
              }
              rel = Lakebed::NsoBuilder::Relocation.new(loc, Lakebed::Elf.const_get(rel), "test_symbol", 8)
              content = "a" * 64
              rel.run(content, 8, symbols)
              
              expected = "a" * 64
              expected[4, expected_value.size] = expected_value
              expect(content).to eq(expected)
            end
          end
        end
      end
    end
    
    describe "#build" do
      it "pads text to page size" do
        builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :dynamic => false)
        builder.add_section("abc", :text)
        expect(builder.build.segments.first[0].size).to eq(0x1000)
      end

      it "includes code in an RX segment" do
        builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :dynamic => false)
        builder.add_section("abc", :text)
        segment = builder.build.segments.first
        expect(segment[0]).to start_with("abc")
        expect(segment[1]).to eq(5)
      end

      it "sets section bases appropriately" do
        builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :dynamic => false)
        sec1 = builder.add_section("abc", :text)
        sec2 = builder.add_section("def", :text)
        sec3 = builder.add_section("ghi", :data)
        
        builder.build

        expect(sec1.nso_location).to eq(0)
        expect(sec2.nso_location).to eq(3)
        expect(sec3.nso_location).to eq(0x1000)
      end

      it "puts symbols at the beginning and end of each segment" do
        builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :dynamic => false)
        sec1 = builder.add_section("abc", :text)
        sec2 = builder.add_section("ghi", :data)
        
        builder.build

        expect(builder.get_symbol("_text_start").to_i).to eq(0)
        expect(builder.get_symbol("_text_end").to_i).to eq(3)
        expect(builder.get_symbol("_rodata_start").to_i).to eq(0x1000)
        expect(builder.get_symbol("_rodata_end").to_i).to eq(0x1000)
        expect(builder.get_symbol("_data_start").to_i).to eq(0x1000)
        expect(builder.get_symbol("_data_end").to_i).to eq(0x1003)
        expect(builder.get_symbol("_bss_start").to_i).to eq(0x2000)
        expect(builder.get_symbol("_bss_end").to_i).to eq(0x2000)
      end
    end

    it "includes a standard NSO prelude" do
      builder = Lakebed::NsoBuilder.new(:prelude => true, :mod0 => false, :dynamic => false)
      builder.add_section("abc", :text)
      segment = builder.build.segments.first
      expect(segment[0]).to start_with("\x02\x00\x00\x14\x00\x00\x00\x00")
    end

    it "relocates the MOD0 offset in the prelude if _mod0 exists" do
      builder = Lakebed::NsoBuilder.new(:prelude => true, :mod0 => false, :dynamic => false)
      builder.add_section("abc", :text)
      mod0_sec = builder.add_section("MOD0", :data)
      builder.add_symbol("_mod0", mod0_sec)
      
      segments = builder.build.segments
      expect(segments[0][0][4, 4].unpack("L<").first).to eq(segments[0][0].bytesize)
      expect(segments[2][0][0, 4]).to eq("MOD0")
    end

    it "generates MOD0 automatically" do
      builder = Lakebed::NsoBuilder.new(:prelude => true, :mod0 => true)
      builder.add_section("abc", :text)
      
      segments = builder.build.segments
      expect(segments[0][0][4, 4].unpack("L<").first).to eq(segments[0][0].bytesize)

      mod0 = segments[2][0].unpack("A4L<L<L<L<L<L<")
      expect(mod0[0]).to eq("MOD0")
      # skip _dynamic_start for now
      expect(mod0[2]).to eq(builder.get_symbol("_bss_start") - builder.get_symbol("_mod0"))
      expect(mod0[3]).to eq(builder.get_symbol("_bss_end") - builder.get_symbol("_mod0"))
      # skip _eh_frame_hdr_start
      # skip _eh_frame_hdr_end
      expect(mod0[6]).to eq(builder.get_symbol("_module_object") - builder.get_symbol("_mod0"))
    end

    it "generates .dynamic and .rela.dyn sections correctly" do
      builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :rel => :rela)
      my_text = builder.add_section("0000111122223333", :text);
      my_text.add_dynamic_relocation(8, Lakebed::Elf::R_AARCH64_RELATIVE, nil, 456)

      nso = builder.build
      expect(nso.read(0, 16)).to eq("0000111122223333") # shouldn't modify original text

      rela_section = nil
      i = builder.get_symbol("_dynamic_start").to_i
      while nso.read(i, 8).unpack("Q<").first != Lakebed::Elf::DT_NULL do
        if nso.read(i, 8).unpack("Q<").first == Lakebed::Elf::DT_RELA then
          rela_section = nso.read(i+8, 8).unpack("Q<")[0]
        end
        if nso.read(i, 8).unpack("Q<").first == Lakebed::Elf::DT_REL then
          raise "has DT_REL tag"
        end
        i+= 16
      end
      if rela_section == nil then
        raise "no DT_RELA tag"
      end
      
      expect(nso.read(rela_section, 0x18)).to eq([8, Lakebed::Elf::R_AARCH64_RELATIVE, 456].pack("Q<Q<Q<"))
    end

    it "generates .rel.dyn section correctly" do
      builder = Lakebed::NsoBuilder.new(:prelude => false, :mod0 => false, :rel => :rel)
      my_text = builder.add_section("0000111122223333", :text);
      my_text.add_dynamic_relocation(8, Lakebed::Elf::R_AARCH64_RELATIVE, nil, 456)

      nso = builder.build
      expect(nso.read(0, 16)).to eq("00001111#{[456].pack("Q<")}") # SHOULD modify original text

      rel_section = nil
      i = builder.get_symbol("_dynamic_start").to_i
      while nso.read(i, 8).unpack("Q<").first != Lakebed::Elf::DT_NULL do
        if nso.read(i, 8).unpack("Q<").first == Lakebed::Elf::DT_RELA then
          raise "has DT_RELA tag"
        end
        if nso.read(i, 8).unpack("Q<").first == Lakebed::Elf::DT_REL then
          rel_section = nso.read(i+8, 8).unpack("Q<")[0]
        end
        i+= 16
      end
      if rel_section == nil then
        raise "no DT_REL tag"
      end
      
      expect(nso.read(rel_section, 0x10)).to eq([8, Lakebed::Elf::R_AARCH64_RELATIVE].pack("Q<Q<"))
    end
end

  describe Lakebed::Emulator do
    it "should map in a stack" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new(:prelude => false)

      # sub sp, sp, #0x10
      # str x0, [sp]
      # b .
      builder.add_section("\xff\x43\x00\xd1\xe0\x03\x00\xf9\x00\x00\x00\x14", :text)
      nso = builder.build

      emu.add_nso(nso)
      emu.begin
    end

    it "should enable NEON" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new(:prelude => false)

      # dup v0.2d, x8
      # b .
      builder.add_section("\x00\x0d\x08\x4e\x00\x00\x00\x14", :text)
      nso = builder.build

      emu.add_nso(nso)
      emu.begin
    end
  end
end
