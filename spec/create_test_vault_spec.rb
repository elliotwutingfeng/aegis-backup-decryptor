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

require 'create_test_vault'
require 'crypto'
require 'pretty'
require 'spec_helper'

describe 'encrypt_vault' do
  it 'Encrypts vault correctly' do
    expected_plain_text = File.read('test/plaintext_test.json', :encoding => 'utf-8')
    password = 'test'
    salt = '27ea9ae53fa2f08a8dcd201615a8229422647b3058f9f36b08f9457e62888be1'
    vault_key = 'W/Pupld1SxdtB26gcHjiKo3z4spavIhuLiX3zvJNEaY='
    password_nonce = 'e9705513ba4951fa7a0608d2'
    vault_nonce = '095fd13dee336fa56b4634ff'
    uuid = 'a8325752-c1be-458a-9b3e-5e0a8154d9ec'

    encrypted_vault_json = encrypt_vault(expected_plain_text, password, [salt].pack('H*'),
                                         vault_key, [password_nonce].pack('H*'),
                                         [vault_nonce].pack('H*'), uuid) # Pretty printed
    encrypted_vault = parse_json(encrypted_vault_json)
    compacted_encrypted_vault_json = encrypted_vault.to_json

    expected_vault_json = parse_json(File.read('test/encrypted_test.json', :encoding => 'utf-8')).to_json # Compacted

    expect(compacted_encrypted_vault_json).to eq expected_vault_json

    # Now decrypt it and check that its plaintext form matches the expected plaintext.
    plain_text, = decrypt_ciphertext(get_db(encrypted_vault), password, encrypted_vault[:header][:slots],
                                     [encrypted_vault[:header][:params][:nonce]].pack('H*'),
                                     [encrypted_vault[:header][:params][:tag]].pack('H*'))
    expect(plain_text).to eq expected_plain_text
  end
  it 'Fails to encrypt empty vault' do
    silence('stderr') do
      expect { encrypt_vault('', '', '', '', '', '', '') }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end
