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
  end
  
  describe Lakebed::NsoBuilder do
    describe "#add_section" do
      it "returns a section" do
        builder = Lakebed::NsoBuilder.new
        expect(builder.add_section("abc", :text)).to be_a(Lakebed::NsoBuilder::Section)
      end
    end

    describe Lakebed::NsoBuilder::Relocation do
      it "refuses to statically relocate absolute addresses" do
        [Lakebed::Elf::R_AARCH64_ABS64, Lakebed::Elf::R_AARCH64_ABS32, Lakebed::Elf::R_AARCH64_ABS16].each do |rel|
          expect do
            loc = instance_double("Lakebed::NsoBuilder::Location", :to_i => 4)
            rel = Lakebed::NsoBuilder::Relocation.new(loc, rel, "test_symbol", 8)
            rel.run(nil, 0, {"test_symbol" => instance_double("Lakebed::NsoBuilder::Location", :to_i => 12)})
          end.to raise_error("can't be run statically")
        end
      end

      {"R_AARCH64_PREL64" => "Q<",
       "R_AARCH64_PREL32" => "L<",
       "R_AARCH64_PREL16" => "S<"}.each_pair do |rel, pack_format|
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
            expected_value = [128 + 8 - 12].pack(pack_format)
            expected[4, expected_value.size] = expected_value
            expect(content).to eq(expected)
          end
        end
      end
    end
    
    describe "#build" do
      it "pads text to page size" do
        builder = Lakebed::NsoBuilder.new
        builder.add_section("abc", :text)
        expect(builder.build.segments.first[0].size).to eq(0x1000)
      end

      it "includes code in an RX segment" do
        builder = Lakebed::NsoBuilder.new
        builder.add_section("abc", :text)
        segment = builder.build.segments.first
        expect(segment[0][8..segment[0].size-1]).to start_with("abc")
        expect(segment[1]).to eq(5)
      end

      it "sets section bases appropriately" do
        builder = Lakebed::NsoBuilder.new(:prelude => false)
        sec1 = builder.add_section("abc", :text)
        sec2 = builder.add_section("def", :text)
        sec3 = builder.add_section("ghi", :data)
        
        builder.build

        expect(sec1.nso_location).to eq(0)
        expect(sec2.nso_location).to eq(3)
        expect(sec3.nso_location).to eq(0x1000)
      end
      
      it "does not create a DT_REL tag if #add_rel is not called" do
      end
    end

    it "includes a standard NSO prelude" do
      builder = Lakebed::NsoBuilder.new
      builder.add_section("abc", :text)
      segment = builder.build.segments.first
      expect(segment[0]).to start_with("\x02\x00\x00\x14\x00\x00\x00\x00")
    end

    it "relocates the MOD0 offset in the prelude if _mod0 exists" do
      builder = Lakebed::NsoBuilder.new
      builder.add_section("abc", :text)
      mod0_sec = builder.add_section("MOD0", :data)
      builder.add_symbol("_mod0", mod0_sec)
      
      segments = builder.build.segments
      expect(segments[0][0][4, 4].unpack("L<").first).to eq(segments[0][0].bytesize)
      expect(segments[2][0][0, 4]).to eq("MOD0")
    end
    
    describe "#add_rel" do
      it "creates valid DT_REL and DT_RELSZ tags" do
      end

      it "includes the relocation in the DT_REL table" do
      end
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
