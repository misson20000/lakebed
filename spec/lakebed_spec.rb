require "lakebed"

RSpec.describe Lakebed do
  def environment
    if @environment then
      return @environment
    end

    @environment = Lakebed::Environment.new(
      Lakebed::TargetVersion.new([1,0,0], 450),
      [0, 9, 1],
      0x00)
  end

  def kernel
    if !@kernel then
      @kernel = Lakebed::Kernel.new(environment)
      @kernel.strict_svcs = true
    end
    @kernel
  end

  def load_sm
    p = Lakebed::Process.new(kernel, :name => "sm")
    File.open("sm.kip") do |f|
      p.add_nso(Lakebed::Files::Kip.from_file(f))
    end
    p
  end
  
  it "reaches startup without crashing" do
    p = load_sm
    p.start
    kernel.continue
  end

  def connect_to_sm(require_accept=true)
    session = nil
    kernel.continue
    session = kernel.named_ports["sm:"].connect
    if require_accept then
      kernel.continue
      expect(session.accepted).to be_truthy
    end
    Lakebed::CMIF::ClientSessionObject.new(session.client)
  end
  
  it "accepts connections to sm:" do
    p = load_sm
    p.start
    kernel.continue

    connect_to_sm(true)
  end

  it "responds to ipc messages" do
    p = load_sm
    p.start
    kernel.continue

    session = connect_to_sm(true)

    session.send_message_sync(
      kernel,
      Lakebed::CMIF::Message.build_rq(0) do
        pid 0
      end).unpack do
    end
  end

  it "does not reply to GetService for a service that has not been registered" do
    p = load_sm
    p.start
    kernel.continue

    session = connect_to_sm(true)
    
    session.send_message(
      Lakebed::CMIF::Message.build_rq(1) do
        u64("fsp-srv\x00".unpack("Q<")[0])
      end) do
      fail "should not reply..."
    end
    
    kernel.continue
  end

  it "replies to GetService for sm:m" do
    p = load_sm
    p.start
    kernel.continue

    session = connect_to_sm(true)
    
    expect(
      session.send_message_sync(
        kernel,
        Lakebed::CMIF::Message.build_rq(1) do
          u64("sm:m\x00\x00\x00\x00".unpack("Q<")[0])
        end))
  end
end
