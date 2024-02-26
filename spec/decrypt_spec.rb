# CLI tool to decrypt backup files exported from the Aegis Authenticator app
# Copyright (C) 2024 Wu Tingfeng <wutingfeng@outlook.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

require 'spec_helper'
require 'decrypt'

# See https://michaelay.github.io/blog/2014/12/15/suppress-stdout-and-stderr-when-running-rspec
def silence
  @original_stderr = $stderr
  @original_stdout = $stdout

  $stderr = $stdout = StringIO.new

  yield

  $stderr = @original_stderr
  $stdout = @original_stdout
  @original_stderr = nil
  @original_stdout = nil
end

describe 'parse_json' do
  it 'Parses valid JSON' do
    expect(parse_json('{"a": [1, 2]}')).to eq({ :a => [1, 2] })
  end
  it 'Exit 1 if invalid JSON' do
    silence do
      expect { parse_json('') }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end

describe 'get_vault_params' do
  it 'Extracts vault parameters if valid' do
    params = get_vault_params(JSON.parse('{
      "header": {"params": {"nonce":"1", "tag": "2"}}
    }', :symbolize_names => true))
    expected = { :iv => ['1'].pack('H*'), :auth_tag => ['2'].pack('H*') }
    params.each do |k, v|
      expect(v).to eq(expected[k])
    end
  end
  it 'Exit 1 if vault parameters are invalid' do
    test_vectors = ['{}',
                    '{"header":{"params":{"nonce":1,"tag":"2"}}}',
                    '{"header":{"params":{"nonce":"1","tag":2}}}'].map do |s|
      JSON.parse(s, :symbolize_names => true)
    end
    silence do
      test_vectors.each do |content|
        expect { get_vault_params(content) }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
end

describe 'extract_password_slots' do
  it 'Exit 1 if no valid slots are found' do
    test_vectors = ['{}', '{"header":""}', '{"header":{"slots":[]}}'].map do |s|
      JSON.parse(s, :symbolize_names => true)
    end
    silence do
      test_vectors.each do |content|
        expect { extract_password_slots(content) }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
end

describe 'get_db' do
  it 'Exit 1 if no db string found' do
    test_vectors = ['[]', '{}', '{"a": ""}'].map do |s|
      JSON.parse(s, :symbolize_names => true)
    end
    silence do
      test_vectors.each do |content|
        expect { get_db(content) }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
end

describe 'main' do
  it 'Correct password -> Decryption success' do
    ARGV.replace ['test/encrypted_test.json']
    allow($stdin).to receive(:noecho) { 'test' } # Backup file password
    output = nil
    expect($stderr).to receive(:puts)
    expect($stdout).to receive(:write) { |arg| output = arg }
    main
    expected_plaintext_vault = File.read('test/plaintext_test.json', :encoding => 'utf-8')
    expect(output).to eq expected_plaintext_vault
  end
  it 'Wrong password -> Decryption failure' do
    ARGV.replace ['test/encrypted_test.json']
    allow($stdin).to receive(:noecho) { '' }
    silence do
      expect { main }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
  it 'Accepts exactly 1 argument' do
    test_vectors = [[], ['test/encrypted_test.json', 'another'], ['test/encrypted_test.json', 'yet another']]
    silence do
      test_vectors.each do |args|
        ARGV.replace args
        expect { main }.to raise_error(SystemExit) do |error|
          expect(error.status).to eq(1)
        end
      end
    end
  end
end
