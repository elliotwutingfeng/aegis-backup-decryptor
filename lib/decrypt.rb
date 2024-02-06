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
require 'io/console'
require 'json'
require 'openssl'

ENCRYPTION_CIPHER = 'aes-256-gcm'.freeze

# DrillPatch provides method `drill` similar to Hash.dig
# but returns nil instead of raising TypeError if it encounters
# an intermediate step that is not a Hash.
module DrillPatch
  def drill(*args)
    node = self
    args.each do |arg|
      return nil unless (node.is_a? Hash) && (node.key? arg)

      node = node[arg]
    end
    node
  end
end
Hash.include DrillPatch

def terminate(message)
  warn message
  exit 1
end

def assert_is_hash(obj)
  return if obj.is_a? Hash

  terminate 'Invalid vault file. Top-level is not Hash.'
end

#
# Parse `plain_text` string as JSON object.
#
# @param [String] plain_text Encoded JSON string
#
# @return [BasicObject] JSON object
#
def parse_json(plain_text)
  JSON.parse(plain_text, :symbolize_names => true)
rescue JSON::ParserError => e
  terminate e.message
end

#
# Extract valid password slots from JSON Hash `obj`.
# Valid password slots match the Aegis Authenticator password slot schema.
#
# @param [Hash] obj JSON Hash
#
# @return [Array] Array of Hash where each Hash may contain parameters needed to derive the master key
#
def extract_password_slots(obj)
  assert_is_hash(obj)
  slots = obj.drill(:header, :slots)
  terminate 'Invalid vault file. No valid password slots found.' unless slots.is_a? Array

  password_slots = slots.select do |slot|
    next if slot.drill(:type) != 1
    next unless slot.drill(:key).is_a? String
    next unless slot.drill(:key_params, :nonce).is_a? String
    next unless slot.drill(:key_params, :tag).is_a? String
    next unless slot.drill(:n).is_a? Integer
    next unless slot.drill(:r).is_a? Integer
    next unless slot.drill(:p).is_a? Integer
    next unless slot.drill(:salt).is_a? String

    true
  end

  terminate 'Invalid vault file. No valid password slots found.' if password_slots.empty?

  password_slots
end

#
# Extract cipher text from `obj` JSON Hash.
#
# @param [Hash] obj JSON Hash
#
# @return [String] Cipher text as bytes
#
def get_db(obj)
  assert_is_hash(obj)
  db = obj[:db]
  terminate 'Invalid vault file. No db found.' unless db.is_a? String
  Base64.strict_decode64 db
end

#
# Extract AES-GCM initialization vector and AES-GCM authentication tag from `obj` JSON Hash.
#
# @param [Hash] obj JSON Hash
#
# @return [Hash] AES-GCM initialization vector and authentication tag
#
def get_vault_params(obj)
  assert_is_hash(obj)

  iv = obj.drill(:header, :params, :nonce)
  terminate 'Invalid vault file. No initialization vector found.' unless iv.is_a? String

  auth_tag = obj.drill(:header, :params, :tag)
  terminate 'Invalid vault file. No authentication tag found.' unless auth_tag.is_a? String

  { :iv => [iv].pack('H*'), :auth_tag => [auth_tag].pack('H*') }
end

#
# Derive the vault master key by trying out `password`
# on all `password_slots` until one succeeds.
#
# @param [String] password Backup file password as plaintext
# @param [Array] password_slots Array of Hash where each Hash may contain parameters needed to derive the master key
#
# @return [String] Derived master key as bytes
#
def derive_master_key(password, password_slots)
  password_slots.each do |slot|
    decipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
    decipher.decrypt
    decipher.key = OpenSSL::KDF.scrypt(password, :salt => [slot[:salt]].pack('H*'), :N => slot[:n],
                                                 :r => slot[:r], :p => slot[:p], :length => 32)
    decipher.iv = [slot.drill(:key_params, :nonce)].pack 'H*'
    decipher.auth_tag = [slot.drill(:key_params, :tag)].pack 'H*'
    decipher.padding = 0

    begin
      return decipher.update([slot[:key]].pack('H*')) + decipher.final
    rescue OpenSSL::Cipher::CipherError
      nil
    end
  end
  terminate 'Failed to derive master key. Wrong password?'
end

#
# Decrypt `cipher_text` and return the plaintext result as String
#
# @param [String] cipher_text Encrypted text as bytes to be decrypted
# @param [String] master_key `cipher_text`'s master key as bytes
# @param [String] iv AES-GCM initialization vector as bytes
# @param [String] auth_tag AES-GCM authentication tag as bytes
#
# @return [String] Decrypted `cipher_text`
#
def decrypt_ciphertext(cipher_text, master_key, iv, auth_tag)
  decipher = OpenSSL::Cipher.new ENCRYPTION_CIPHER
  decipher.decrypt
  decipher.key = master_key
  decipher.iv = iv
  decipher.auth_tag = auth_tag
  decipher.padding = 0

  decipher.update(cipher_text) + decipher.final
end

#
# Prompt terminal user for password.
# A drop-in replacement for $stdin.getpass for older Ruby versions.
#
# @param [String] prompt Message prompt to display
#
# @return [String] Password as plaintext
#
def getpass(prompt)
  $stderr.write prompt # Display prompt without adding prompt to stdout.
  password = $stdin.noecho(&:gets).chomp
  $stderr.puts # Display newline without adding newline to stdout.
  password
end

def main
  terminate 'Usage: decrypt.rb <filename>' if ARGV.length != 1

  obj = parse_json File.read(ARGV[0], :encoding => 'utf-8')
  password_slots = extract_password_slots(obj)
  cipher_text = get_db(obj)
  iv, auth_tag = get_vault_params(obj).values_at(:iv, :auth_tag)

  password = getpass('Enter Aegis encrypted backup password: ')
  master_key = derive_master_key(password, password_slots)
  plain_text = decrypt_ciphertext(cipher_text, master_key, iv, auth_tag)
  parse_json(plain_text) # Ensure plain_text is valid JSON.

  $stdout.write plain_text
end

main if __FILE__ == $PROGRAM_NAME
