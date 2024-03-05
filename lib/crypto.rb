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

require 'openssl'

ENCRYPTION_CIPHER = 'aes-256-gcm'.freeze

#
# Derive a key using scrypt.
#
# @param [String] password KDF password as plaintext
# @param [String] salt KDF salt as bytes
# @param [Integer] n CPU/memory cost parameter. This must be a power of 2
# @param [Integer] r Block size parameter
# @param [Integer] p Parallelization parameter
# @param [Integer] length Length in octets of the derived key
#
# @return [String] Derived key
#
def derive_key(password, salt, n, r, p, length)
  OpenSSL::KDF.scrypt(password, :salt => salt, :N => n, :r => r, :p => p, :length => length)
end

#
# Decrypt the vault master key by trying out `password`
# on all `password_slots` until one succeeds.
#
# @param [String] password KDF password as plaintext
# @param [Array] password_slots Array of Hash where each Hash may contain parameters needed to decrypt the master key
#
# @return [String] Decrypted key
#
def decrypt_master_key(password, password_slots)
  password_slots.each do |slot|
    begin
      meta_key = derive_key(password, [slot[:salt]].pack('H*'), slot[:n], slot[:r], slot[:p], 32)
      master_key, = aes_gcm([slot[:key]].pack('H*'), meta_key, [slot.drill(:key_params, :nonce)].pack('H*'),
                            false, [slot.drill(:key_params, :tag)].pack('H*'))
      return master_key
    rescue OpenSSL::Cipher::CipherError, ArgumentError
      nil
    end
  end
  terminate 'Failed to decrypt master key. Wrong password?'
end

#
# Perform AES-GCM encryption or decryption.
#
# @param [String] text Text to be encrypted or decrypted
# @param [String] master_key AES-GCM master key
# @param [String] iv AES-GCM initialization vector
# @param [Boolean] encrypt Specify whether encryption or decryption should be performed
# @param [String, nil] auth_tag AES-GCM authentication tag used for decryption. Will not be used if `encrypt` is true.
#
# @return [Array<String>] 2-element Array where first element is resulting ciphertext or plaintext, and second element
#  is the AES-GCM authentication tag
#
def aes_gcm(text, master_key, iv, encrypt, auth_tag = nil)
  cipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  if encrypt
    cipher.encrypt
  else
    cipher.decrypt
  end
  cipher.key = master_key
  cipher.iv = iv
  cipher.auth_tag = auth_tag unless encrypt
  cipher.auth_data = ''
  cipher.padding = 0

  [cipher.update(text) + cipher.final, encrypt ? cipher.auth_tag : auth_tag]
end

#
# Decrypt `cipher_text` and return the plaintext result as String.
#
# @param [String] cipher_text bytes to be decrypted
# @param [String] password KDF password as plaintext
# @param [Array] password_slots Array of Hash where each Hash may contain parameters needed to decrypt the master key
# @param [String] iv AES-GCM initialization vector as bytes
# @param [String] auth_tag AES-GCM authentication tag as bytes
#
# @return [Array<String>] 2-element Array where first element is resulting plaintext, and second element
#  is the AES-GCM authentication tag
#
def decrypt_ciphertext(cipher_text, password, password_slots, iv, auth_tag)
  encrypt = false
  master_key = decrypt_master_key(password, password_slots)
  aes_gcm(cipher_text, master_key, iv, encrypt, auth_tag)
rescue OpenSSL::Cipher::CipherError, ArgumentError => e
  terminate "Failed to decrypt vault. #{e.instance_of?(ArgumentError) ? e.message : 'Vault may be corrupted.'}"
end
