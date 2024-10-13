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

require 'base64'
require 'json'

require_relative 'crypto'

#
# Encrypt vault with given AES-GCM parameters.
# If successful, return encrypted vault as JSON String.
#
# The vault_key and vault_nonce are used to encrypt the plain_text, following which the vault_key itself is encrypted
# with a meta_key derived from the password and salt, and a password_nonce. This encrypted_vault_key is then stored in
# the first slot.
#
# Reference: https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md
#
# @param [String] plain_text Vault contents
# @param [String] password First slot password
# @param [String] salt First slot salt as bytes
# @param [String] vault_key Vault master key as base64 strict encoded String
# @param [String] password_nonce First slot AES-GCM initialization vector as bytes
# @param [String] vault_nonce Vault AES-GCM initialization vector as bytes
# @param [String] uuid First slot UUIDv4 identifier
#
# @return [String] Encrypted vault as JSON String
#
def encrypt_vault(plain_text, password, salt, vault_key, password_nonce, vault_nonce, uuid)
  n = 32_768
  r = 8
  p = 1
  length = 32

  # Encrypt the plain_text
  encrypted_plain_text, vault_tag = aes_gcm(plain_text, Base64.strict_decode64(vault_key), vault_nonce, true)

  # Derive the meta_key
  meta_key = derive_key(password, salt, n, r, p, length)

  # Encrypt the vault_key using the meta_key
  encrypted_vault_key, password_tag = aes_gcm(Base64.strict_decode64(vault_key), meta_key, password_nonce, true)

  JSON.pretty_generate({
                         :version => 1,
                         :header => {
                           :slots => [
                             {
                               :type => 1,
                               :uuid => uuid,
                               :key => encrypted_vault_key.unpack1('H*'),
                               :key_params => {
                                 :nonce => password_nonce.unpack1('H*'),
                                 :tag => password_tag.unpack1('H*')
                               },
                               :n => n,
                               :r => r,
                               :p => p,
                               :salt => salt.unpack1('H*'),
                               :repaired => true
                             }
                           ],
                           :params => {
                             :nonce => vault_nonce.unpack1('H*'),
                             :tag => vault_tag.unpack1('H*')
                           }
                         },
                         :db => Base64.strict_encode64(encrypted_plain_text)
                       }, :indent => '    ')
rescue ArgumentError => e
  abort "Failed to encrypt vault. #{e.instance_of?(ArgumentError) ? e.message : 'Invalid parameters?'}"
end
