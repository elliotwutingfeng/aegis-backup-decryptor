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

require 'csv'
require_relative 'decrypt'

#
# Recursively flatten a nested JSON object into a single-level hash
#
# @param [Hash] json_data JSON object to be flattened
# @param [String] parent_key Parent key for the current level
#
# @return [Hash] Flattened JSON data where keys are concatenated
#  with dots to represent nested structure
#
def flatten_json(json_data, parent_key)
  json_data.each_with_object({}) do |(key, value), hash|
    new_key = parent_key.empty? ? key.to_sym : :"#{parent_key}.#{key}"
    if value.is_a?(Hash)
      hash.merge!(flatten_json(value, new_key))
    else
      hash[new_key] = value
    end
  end
end

#
# Convert JSON array under :entries key of JSON string plain_text to CSV String
#
# @param [String] plain_text JSON String
#
# @return [String] CSV String
#
def entries_to_csv(plain_text)
  json_data = parse_json(plain_text)[:entries]
  flattened_data = json_data.map { |record| flatten_json(record, '') }
  headers = flattened_data.first.keys

  CSV.generate do |csv|
    csv << headers
    flattened_data.each do |record|
      csv << headers.map { |header| record[header] }
    end
  end
end

#
# Make a beautiful CSV-like String padded with spaces
#
# @param [String] raw_csv CSV String
#
# @return [String] Beautiful CSV-like String padded with spaces
#
def beautify(raw_csv)
  csv_data = CSV.parse(raw_csv)
  column_widths = Array.new(csv_data.first.length, 0) # Calculate column widths.
  csv_data.each do |row|
    row.each_with_index do |cell, index|
      column_widths[index] = [column_widths[index], cell.to_s.length].max
    end
  end

  output = '' # Pretty print CSV with justified columns.
  csv_data.each do |row|
    row.each_with_index do |cell, index|
      output << cell.to_s.ljust(column_widths[index] + 2) # Pad with 2 spaces.
    end
    output << "\n"
  end
  output
end

print beautify entries_to_csv($stdin.read) if __FILE__ == $PROGRAM_NAME
