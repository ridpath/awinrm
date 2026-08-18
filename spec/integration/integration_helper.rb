# frozen_string_literal: true

# Integration test harness for AWINRM.
#
# These specs talk to a REAL Windows test VM over WinRM. They are inert by
# default: every example tagged `integration: true` skips unless
# AWINRM_INTEGRATION=1 AND the WINRM_TEST_* credentials are present.
#
# Environment variables (set as GitHub repo variables/secrets to run in CI,
# or exported locally before `bundle exec rspec spec/integration`):
#
#   AWINRM_INTEGRATION   "1" to enable (anything else disables)
#   WINRM_TEST_HOST      target IP or hostname (required)
#   WINRM_TEST_PORT      WinRM port (default 5985; 5986 implies SSL)
#   WINRM_TEST_USER      target username (required)
#   WINRM_TEST_PASSWORD  target password (required unless WINRM_TEST_HASH)
#   WINRM_TEST_HASH      NTLM hash for pass-the-hash (optional alternative)
#   WINRM_TEST_SSL       "1" to force HTTPS (default: inferred from port)
#
# The CI job always runs this suite; without the env above the specs skip
# and the job stays green. (Do NOT gate the CI job with a job-level
# `if: env.*` — the env context is unavailable at job-level if evaluation
# and a malformed if aborts the entire workflow dispatch.)

require 'spec_helper'
require_relative '../../lib/evil_ctf/connection'

module AwinrmIntegration
  module_function

  def enabled?
    ENV.fetch('AWINRM_INTEGRATION', '0') == '1' &&
      !ENV['WINRM_TEST_HOST'].to_s.empty? &&
      !ENV['WINRM_TEST_USER'].to_s.empty? &&
      (!ENV['WINRM_TEST_PASSWORD'].to_s.empty? || !ENV['WINRM_TEST_HASH'].to_s.empty?)
  end

  def skip_reason
    if ENV.fetch('AWINRM_INTEGRATION', '0') == '1'
      'missing WINRM_TEST_HOST / WINRM_TEST_USER / WINRM_TEST_PASSWORD or WINRM_TEST_HASH'
    else
      'AWINRM_INTEGRATION=1 not set — integration tests disabled'
    end
  end

  # Keyword args for EvilCTF::Connection.build_full (only options it forwards).
  def build_opts
    port = (ENV['WINRM_TEST_PORT'] || '5985').to_i
    opts = {
      ip: ENV.fetch('WINRM_TEST_HOST', nil),
      port: port,
      user: ENV.fetch('WINRM_TEST_USER', nil),
      password: ENV['WINRM_TEST_PASSWORD'] || '',
      hash: ENV.fetch('WINRM_TEST_HASH', nil),
      ssl: ENV['WINRM_TEST_SSL'] == '1' || port == 5986
    }
    opts.compact
  end

  # Generous per-command timeout: test VMs on CI networks are slow.
  RUN_TIMEOUT = 120

  # Close a shell without letting teardown errors mask assertion failures.
  def safe_close(obj)
    obj&.close
  rescue StandardError
    nil
  end
end

RSpec.configure do |config|
  config.before(:each, integration: true) do
    skip AwinrmIntegration.skip_reason unless AwinrmIntegration.enabled?
  end
end
