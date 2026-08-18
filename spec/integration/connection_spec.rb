# frozen_string_literal: true

require_relative 'integration_helper'
require_relative '../../lib/evil_ctf/execution'

# NOTE: connections and shells are created lazily (inside examples or via
# `let`) and never in before(:all) — the integration skip hook runs in
# before(:each), so any eager work in before(:all) would execute on a
# disabled (skipped) suite.
RSpec.describe 'Live WinRM connection', integration: true do
  let(:conn) { EvilCTF::Connection.build_full(**AwinrmIntegration.build_opts) }
  let(:shell) { conn.shell(:powershell) }

  it 'builds a connection object' do
    expect(conn).to be_a(WinRM::Connection)
  end

  it 'validates via ConnectionValidator and reports a hostname' do
    # The validator opens and closes its own shell.
    result = EvilCTF::ConnectionValidator.validate(conn, timeout: AwinrmIntegration::RUN_TIMEOUT)
    expect(result[:ok]).to eq(true), "validation failed: #{result[:error]}"
    expect(result[:hostname]).to match(/\S/)
  end

  it 'executes a remote command via Execution.run' do
    result = EvilCTF::Execution.run(shell, 'whoami /fo csv /ns #', timeout: AwinrmIntegration::RUN_TIMEOUT)
    expect(result.exitcode).to eq(0)
    expect(result.output).to match(/^#/)
    expect(result.output).to include('user')
  ensure
    AwinrmIntegration.safe_close(shell)
  end

  it 'reports OS product data' do
    result = EvilCTF::Execution.run(shell, 'systeminfo | Select-String "OS Name|OS Version"',
                                    timeout: AwinrmIntegration::RUN_TIMEOUT)
    expect(result.exitcode).to eq(0)
    expect(result.output).to match(/OS Name/i)
  ensure
    AwinrmIntegration.safe_close(shell)
  end
end
