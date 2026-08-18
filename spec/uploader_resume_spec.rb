# frozen_string_literal: true

require 'base64'
require 'digest'
require 'tmpdir'
require 'spec_helper'
require_relative '../lib/evil_ctf/uploader'
require_relative '../lib/evil_ctf/uploader/client'
require_relative '../lib/evil_ctf/errors'

CHUNK = 64 * 1024

# Emulates the remote side in memory: partial file, its .part.meta
# sidecar, and the final file. Interprets the PowerShell commands the
# client sends and responds like the target would.
class UploaderResumeFakeTarget
  attr_reader :commands
  attr_accessor :partial, :meta, :final

  def initialize
    @partial = nil
    @meta = nil
    @final = nil
    @commands = []
  end

  def as_shell
    target = self
    Class.new do
      define_method(:run) { |cmd| target.handle(cmd.to_s) }
      define_method(:close) { nil }
      define_method(:adapter_info) { { type: :fake } }
    end.new
  end

  def handle(cmd)
    @commands << cmd
    if cmd.include?('$PSVersionTable')
      reply('5.1.22621.1')
    elsif cmd.include?('STATE::')
      reply("STATE::#{@partial&.bytesize.to_i}::#{@meta || 'NONE'}")
    elsif cmd.include?('SetLength')
      trim(cmd)
    elsif cmd.include?('WriteAllText')
      init(cmd)
    elsif cmd.include?('FromBase64String')
      append_chunk(cmd)
    elsif cmd.include?('Move-Item') || cmd.include?('Copy-Item')
      @final = @partial
      @partial = nil
      reply('MOVED')
    elsif cmd.include?('Get-FileHash')
      hash_command(cmd)
    elsif cmd.include?('Remove-Item')
      remove_command(cmd)
    elsif cmd.include?('.Length')
      length_command(cmd)
    else
      reply('OK')
    end
  end

  private

  def reply(output)
    OpenStruct.new(exitcode: 0, output: output)
  end

  def trim(cmd)
    m = cmd.match(/SetLength\((\d+)\)/)
    @partial = @partial[0...m[1].to_i] if @partial && m
    reply('TRIMMED')
  end

  def init(cmd)
    m = cmd.match(/WriteAllText\('[^']+', '([0-9a-f]{64})'\)/)
    @partial = +''
    @meta = m[1] if m
    reply('INIT')
  end

  def append_chunk(cmd)
    m = cmd.match(%r{@'\n([A-Za-z0-9+/=]+)\n'@})
    raise 'no base64 payload in command' unless m

    @partial ||= +''
    @partial << Base64.decode64(m[1])
    reply(cmd) # echoes "CHUNK n"
  end

  def hash_command(cmd)
    content = cmd.include?('.part') ? @partial : @final
    reply(content ? Digest::SHA256.hexdigest(content) : 'MISSING')
  end

  def remove_command(cmd)
    if cmd.include?('.part.meta')
      @meta = nil
    elsif cmd.include?('.part')
      @partial = nil
    else
      @final = nil
    end
    reply('OK')
  end

  def length_command(cmd)
    len = if cmd.include?('.part') && @partial
            @partial.bytesize
          elsif @final
            @final.bytesize
          else
            0
          end
    reply(len.to_s)
  end
end

RSpec.describe EvilCTF::Uploader::Client, 'upload resume' do
  let(:target) { UploaderResumeFakeTarget.new }
  let(:client) { described_class.new(target.as_shell, nil) }

  around do |example|
    Dir.mktmpdir('awinrm-resume-test') do |dir|
      @dir = dir
      example.run
    end
  end

  def write_local(bytes)
    path = File.join(@dir, 'payload.bin')
    File.binwrite(path, bytes)
    path
  end

  def upload(path, **kw)
    client.upload_file(local_path: path, remote_path: 'C:\\Users\\Public\\payload.bin',
                       chunk_size: CHUNK, **kw)
  end

  def chunk_commands
    target.commands.count { |c| c.include?('FromBase64String') }
  end

  it 'uploads a fresh file end-to-end when no partial exists' do
    bytes = 'A' * ((CHUNK * 3) + 123)
    result = upload(write_local(bytes), verify: true)
    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(bytes)
    expect(chunk_commands).to eq(4)
    expect(target.commands.any? { |c| c.include?('SetLength') }).to eq(false)
  end

  it 'resumes from a compatible partial without re-init' do
    bytes = 'B' * ((CHUNK * 4) + 55)
    expected_meta = Digest::SHA256.hexdigest(bytes)
    target.partial = +bytes[0...(CHUNK * 2)]
    target.meta = expected_meta

    result = upload(write_local(bytes), verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(bytes)
    expect(chunk_commands).to eq(3) # only the tail chunks (2 full + 55-byte remainder)
    expect(target.commands.any? { |c| c.include?('WriteAllText') }).to eq(false)
  end

  it 'trims a ragged partial to a chunk boundary before resuming' do
    bytes = 'C' * ((CHUNK * 2) + 10)
    target.partial = +bytes[0...(CHUNK + 4096)] # ragged: 1 chunk + 4KB
    target.meta = Digest::SHA256.hexdigest(bytes)

    result = upload(write_local(bytes), verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(bytes)
    expect(target.commands.any? { |c| c.include?('SetLength(65536)') }).to eq(true)
    expect(chunk_commands).to eq(2)
  end

  it 'starts fresh when the sidecar hash does not match the local file' do
    bytes = 'D' * (CHUNK * 2)
    target.partial = +bytes[0...CHUNK]
    target.meta = 'f' * 64

    result = upload(write_local(bytes), verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(bytes)
    expect(target.commands.any? { |c| c.include?('WriteAllText') }).to eq(true)
    expect(chunk_commands).to eq(2)
  end

  it 'starts fresh when the partial has no sidecar' do
    bytes = 'E' * (CHUNK * 2)
    target.partial = +bytes[0...CHUNK]
    target.meta = nil

    result = upload(write_local(bytes), verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.commands.any? { |c| c.include?('WriteAllText') }).to eq(true)
  end

  it 'honors resume: false by forcing a fresh upload' do
    bytes = 'F' * (CHUNK * 2)
    target.partial = +bytes[0...CHUNK]
    target.meta = Digest::SHA256.hexdigest(bytes)

    result = upload(write_local(bytes), resume: false, verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.commands.any? { |c| c.include?('WriteAllText') }).to eq(true)
    expect(chunk_commands).to eq(2)
  end

  it 'skips chunking entirely when the partial already holds the full file' do
    bytes = 'G' * CHUNK * 3
    target.partial = +bytes.dup
    target.meta = Digest::SHA256.hexdigest(bytes)

    result = upload(write_local(bytes), verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(bytes)
    expect(chunk_commands).to eq(0)
  end

  it 'keeps the partial and sidecar after a failed chunk for the next resume' do
    bytes = 'H' * (CHUNK * 2)
    state = { failed: false }
    shell = target.as_shell
    # Make the FIRST chunk write blow up
    wrapped = Class.new do
      define_method(:run) do |cmd|
        c = cmd.to_s
        if c.include?('FromBase64String') && !state[:failed]
          state[:failed] = true
          raise 'connection dropped'
        end
        shell.run(c)
      end
      define_method(:close) { nil }
      define_method(:adapter_info) { { type: :fake } }
    end.new
    flaky_client = described_class.new(wrapped, nil)

    expect do
      flaky_client.upload_file(local_path: write_local(bytes),
                               remote_path: 'C:\\Users\\Public\\payload.bin',
                               chunk_size: CHUNK, verify: true)
    end
      .to raise_error(EvilCTF::Errors::UploadError)

    expect(target.partial).not_to be_nil
    expect(target.partial.bytesize).to eq(0) # nothing written before the failure
    expect(target.meta).to eq(Digest::SHA256.hexdigest(bytes))
  end

  it 'verifies XOR uploads against the transformed hash' do
    bytes = 'I' * ((CHUNK * 2) + 7)
    key = 0x42
    result = upload(write_local(bytes), xor_key: key, verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(EvilCTF::Tools::Crypto.xor_crypt(bytes, key))
    expect(result[:remote_hash]).to eq(Digest::SHA256.hexdigest(EvilCTF::Tools::Crypto.xor_crypt(bytes, key)))
  end

  it 'resumes an interrupted XOR upload using the transformed sidecar hash' do
    bytes = 'J' * ((CHUNK * 2) + 7)
    key = 0x42
    transformed = EvilCTF::Tools::Crypto.xor_crypt(bytes, key)
    target.partial = +transformed[0...CHUNK]
    target.meta = Digest::SHA256.hexdigest(transformed)

    result = upload(write_local(bytes), xor_key: key, verify: true)

    expect(result[:ok]).to eq(true)
    expect(target.final).to eq(transformed)
    expect(chunk_commands).to eq(2)
  end
end
