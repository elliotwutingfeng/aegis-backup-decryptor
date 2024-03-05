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
require 'optparse'

require_relative 'crypto'
require_relative 'pretty'

#
# DrillPatch provides method `drill` similar to Hash.dig
# but returns nil instead of raising TypeError if it encounters
# an intermediate step that is not a Hash.
#
module DrillPatch
  #
  # Traverse a nested hash to access a value.
  #
  # @param [Array<Object>] args A list of keys to traverse the nested hash
  # @return [Object, nil] The value found at the specified nested key path, or `nil` if not found
  #
  # @example
  #   h = { a: { b: { c: 42 } } }
  #   h.extend(DrillPatch)
  #   h.drill(:a, :b, :c) #=> 42
  #   h.drill(:a, :b, :c, :d) #=> nil
  #
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
# Extract valid password slots from JSON Hash `obj`.
# Valid password slots match the Aegis Authenticator password slot schema.
#
# @param [Hash] obj JSON Hash
#
# @return [Array] Array of Hash where each Hash may contain parameters needed to decrypt the master key
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
  terminate 'Invalid vault file. No db found.' unless obj.key?(:db)
  db = obj[:db]
  terminate 'Invalid vault file. db is not a String.' unless db.is_a? String
  Base64.strict_decode64 db
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

#
# Parse vault parameters from vault at `filename`.
#
# @param [String] filename Vault filename
#
# @return [Hash] Vault parameters
#
def parse_vault_params(filename)
  begin
    obj = parse_json File.read(filename, :encoding => 'utf-8')
  rescue Errno::ENOENT => e
    terminate e.to_s
  end
  assert_is_hash(obj)
  password_slots = extract_password_slots(obj)
  cipher_text = get_db(obj)
  iv = obj.drill(:header, :params, :nonce)
  terminate 'Invalid vault file. No initialization vector found.' unless iv.is_a? String
  auth_tag = obj.drill(:header, :params, :tag)
  terminate 'Invalid vault file. No authentication tag found.' unless auth_tag.is_a? String
  version = obj.drill(:version)
  warn 'WARNING: Vault format version is not 1. Decryption may either fail completely or produce wrong results.' unless
  version == 1

  { :password_slots => password_slots, :cipher_text => cipher_text, :iv => [iv].pack('H*'),
    :auth_tag => [auth_tag].pack('H*') }
end

def parse_args
  formats = %i[json csv pretty]
  options = { :format => :json, :except => [] }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} <filename> [options]"
    opts.on('-f FORMAT', '--format FORMAT', formats,
            "Plaintext vault output format; pick one from #{formats.map(&:to_s)}") do |f|
      options[:format] = f
    end
    opts.on('-e', '--except x,y,z', Array, 'Specify fields to hide; for example, `-e icon,info.counter,uuid`') do |e|
      options[:except] = e
    end
    opts.on_tail('-h', '--help', 'Show this message') do
      puts opts
      exit 0
    end
  end

  begin
    parser.parse! ARGV
    raise StandardError, "invalid number of arguments: expected 1, got #{ARGV.length}" if ARGV.length != 1

    if options[:format] == :json && !options[:except].empty?
      raise StandardError,
            'hiding fields is only supported for `csv` and `pretty` formats'
    end
  rescue StandardError => e
    terminate "#{e}\n#{parser}"
  end
  options
end

#
# Accept vault filename as a command-line argument, and optionally output format and fields to exclude.
# Decrypt the vault and write its contents to $stdout in specified output format.
#
# @param [String] filename Vault file to decrypt
# @param [String] format Output format (Default: json)
#
def main
  options = parse_args
  vault_params = parse_vault_params ARGV[0]
  vault_params[:password] = getpass('Enter Aegis encrypted backup password: ')
  plain_text, = decrypt_ciphertext(vault_params[:cipher_text], vault_params[:password], vault_params[:password_slots],
                                   vault_params[:iv], vault_params[:auth_tag])
  parse_json(plain_text) # Ensure plain_text is valid JSON.

  $stdout.write case options[:format]
                when :pretty
                  beautify remove_fields(entries_to_csv(plain_text), options[:except])
                when :csv
                  remove_fields(entries_to_csv(plain_text), options[:except])
                else
                  plain_text
                end
end

main if __FILE__ == $PROGRAM_NAME
