require_relative 'spec_helper'
require_relative '../lib/evil_ctf/shell_adapter'
require_relative '../lib/evil_ctf/errors'

class DummyShell
  def run(cmd)
    Struct.new(:exitcode, :output).new(0, 'OK')
  end
  def close; end
end

RSpec.describe EvilCTF::ShellAdapter do
  it 'wraps a generic object that implements run/close' do
    dummy = DummyShell.new
    adapter = EvilCTF::ShellAdapter.wrap(dummy)
    expect(adapter).to respond_to(:run)
    expect(adapter).to respond_to(:close)
    res = adapter.run('echo hi')
    expect(res.output).to eq('OK')
  end
end
