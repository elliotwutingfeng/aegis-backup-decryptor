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

require 'crypto'
require 'pretty'
require 'spec_helper'

describe 'decrypt_ciphertext' do
  it 'Fails to decrypt corrupted ciphertext' do
    encrypted_vault = parse_json(File.read('test/encrypted_test.json', :encoding => 'utf-8'))
    # Correct password, master_key decrypted
    password = 'test'
    password_slots = encrypted_vault[:header][:slots]
    iv = [encrypted_vault[:header][:params][:nonce]].pack('H*')
    auth_tag = [encrypted_vault[:header][:params][:tag]].pack('H*')

    # Bad ciphertext
    expect { decrypt_ciphertext('', password, password_slots, iv, auth_tag) }.to raise_error(SystemExit) do |error|
      expect(error.status).to eq(1)
    end
  end
end
