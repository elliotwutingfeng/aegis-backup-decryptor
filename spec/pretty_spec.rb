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
require 'pretty'

describe 'pretty' do
  it 'Pretty prints plain text vault as a CSV-like String padded with spaces' do
    expected_pretty_vault = File.read('test/pretty_test.txt', :encoding => 'utf-8')
    expect(beautify(entries_to_csv(File.read('test/plaintext_test.json',
                                             :encoding => 'utf-8')))).to eq expected_pretty_vault
  end
end
