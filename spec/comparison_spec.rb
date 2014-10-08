
require 'spec_helper'

describe IPTables do
  describe 'multiple tables comparison' do
    before :context do
      @table1 = <<-EOS
*table1
:chain1 ACCEPT [0:0]
:chain2 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
      EOS
      @table2 = <<-EOS
*table2
:chain3 ACCEPT [0:0]
:chain4 ACCEPT [0:0]
-A chain3 -m comment --comment "comment3"
-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
-A chain4 -m comment --comment "comment4"
-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT
-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT
COMMIT
      EOS
      @iptables1 = IPTables::Tables.new( "#{@table1}\n#{@table2}" )
    end
    it "should fail with an invalid table" do
      expect { IPTables::TablesComparison.new nil, @iptables1 }.to raise_error(RuntimeError)
      expect { IPTables::TablesComparison.new @iptables1, nil }.to raise_error(RuntimeError)
    end
    it "should show identical tables as equal" do
      iptables2 = IPTables::Tables.new( "#{@table1}\n#{@table2}" )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      expect(comparison.equal?).to be true
      expect(comparison.as_array).to eq []
    end
    it "should catch a missing table" do
      iptables2 = IPTables::Tables.new( @table1 )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      expect(comparison.equal?).to be false
      expect(comparison.as_array).to eq [
        "Missing table: table2",
        ":chain3 ACCEPT",
        ":chain4 ACCEPT",
        "-A chain3 -m comment --comment \"comment3\"",
        "-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT",
        "-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT",
        "-A chain4 -m comment --comment \"comment4\"",
        "-A chain4 -p tcp -m tcp --dport 7 -j ACCEPT",
        "-A chain4 -p tcp -m tcp --dport 8 -j ACCEPT",
      ]
    end
    it "should catch an additional table" do
      table3 = <<-EOS
*table3
:chain5 ACCEPT [0:0]
:chain6 ACCEPT [0:0]
-A chain5 -m comment --comment "comment5"
-A chain5 -p tcp -m tcp --dport 9 -j ACCEPT
-A chain5 -p tcp -m tcp --dport 10 -j ACCEPT
-A chain6 -m comment --comment "comment6"
-A chain6 -p tcp -m tcp --dport 11 -j ACCEPT
-A chain6 -p tcp -m tcp --dport 12 -j ACCEPT
COMMIT
      EOS
      iptables2 = IPTables::Tables.new( "#{@table1}\n#{@table2}\n#{table3}" )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      expect(comparison.equal?).to be false
      expect(comparison.as_array).to eq [
        "New table: table3",
        ":chain5 ACCEPT",
        ":chain6 ACCEPT",
        "-A chain5 -m comment --comment \"comment5\"",
        "-A chain5 -p tcp -m tcp --dport 9 -j ACCEPT",
        "-A chain5 -p tcp -m tcp --dport 10 -j ACCEPT",
        "-A chain6 -m comment --comment \"comment6\"",
        "-A chain6 -p tcp -m tcp --dport 11 -j ACCEPT",
        "-A chain6 -p tcp -m tcp --dport 12 -j ACCEPT",
      ]
    end
    it "should catch a differing rule" do
      table1 = <<-EOS
*table1
:chain1 ACCEPT [0:0]
:chain2 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
      EOS
      iptables2 = IPTables::Tables.new( "#{table1}\n#{@table2}" )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      expect(comparison.equal?).to be false
      expect(comparison.as_array).to eq [
        "Changed table: table1",
        "Changed chain: chain1",
        "-1: -A chain1 -p tcp -m tcp --dport 1 -j ACCEPT",
        "+1: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT"
      ]
    end
    it "should catch a changed comment when include_comments" do
      table1 = <<-EOS
*table1
:chain1 ACCEPT [0:0]
:chain2 ACCEPT [0:0]
-A chain1 -m comment --comment "changed comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
      EOS
      iptables2 = IPTables::Tables.new( "#{table1}\n#{@table2}" )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      comparison.include_comments
      expect(comparison.equal?).to be false
      expect(comparison.as_array).to eq [
        "Changed table: table1",
        "Changed chain: chain1",
        "-0: -A chain1 -m comment --comment \"comment1\"",
        "+0: -A chain1 -m comment --comment \"changed comment1\"",
      ]
    end
    it "should not catch a changed comment when ignore_comments" do
      table1 = <<-EOS
*table1
:chain1 ACCEPT [0:0]
:chain2 ACCEPT [0:0]
-A chain1 -m comment --comment "changed comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
      EOS
      iptables2 = IPTables::Tables.new( "#{table1}\n#{@table2}" )
      comparison = IPTables::TablesComparison.new(@iptables1, iptables2)
      comparison.ignore_comments
      expect(comparison.equal?).to be true
      expect(comparison.as_array).to eq []
    end
  end
  describe 'single table comparison' do
    before :context do
      @table_text = <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
:chain2 ACCEPT [0:0]
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
      EOS
      @table1 = IPTables::Tables.new( @table_text ).tables['table1']
    end
    it "should raise a RuntimeError if compared with a non-table" do
      expect { IPTables::TableComparison.new nil, @table1 }.to raise_error RuntimeError
      expect { IPTables::TableComparison.new @table1, nil }.to raise_error RuntimeError
    end
    it "should show that a table is equal to itself" do
      table2 = IPTables::Tables.new( @table_text ).tables['table1']
      comparison = IPTables::TableComparison.new(@table1, table2)
      expect(comparison.equal?).to be true
      expect(comparison.as_array).to eq []
    end
    it "should raise a RuntimeError when comparing tables with different names" do
      table2 = IPTables::Tables.new(
        <<-EOS
*table2
COMMIT
        EOS
      ).tables['table2']
      # comparison = IPTables::TableComparison.new(@table1, table2)
      expect { IPTables::TableComparison.new(@table1, table2) }.to raise_error RuntimeError, 'table names should match'
    end
    it "should notice a missing chain" do
      table2 = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
        EOS
      ).tables['table1']
      comparison = IPTables::TableComparison.new(@table1, table2)
      expect(comparison.equal?).to be false
      expect(comparison.missing).to eq ['chain2']
      expect(comparison.as_array).to eq [
        'Changed table: table1',
        'Missing chain:',
        ':chain2 ACCEPT',
        '-A chain2 -m comment --comment "comment2"',
        '-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT',
        '-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT'
      ]
    end
    it "should notice an additional chain" do
      table2 = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
:chain2 ACCEPT [0:0]
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
:chain3 ACCEPT [0:0]
-A chain3 -m comment --comment "comment3"
-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT
-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT
COMMIT
        EOS
      ).tables['table1']
      comparison = IPTables::TableComparison.new(@table1, table2)
      expect(comparison.equal?).to be false
      expect(comparison.new).to eq ['chain3']
      expect(comparison.as_array).to eq [
        'Changed table: table1',
        'New chain:',
        ':chain3 ACCEPT',
        '-A chain3 -m comment --comment "comment3"',
        '-A chain3 -p tcp -m tcp --dport 5 -j ACCEPT',
        '-A chain3 -p tcp -m tcp --dport 6 -j ACCEPT'
      ]
    end
    it "should notice a modified chain" do
      table2 = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
:chain2 ACCEPT [0:0]
-A chain2 -m comment --comment "comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
        EOS
      ).tables['table1']
      comparison = IPTables::TableComparison.new(@table1, table2)
      expect(comparison.equal?).to be false
      expect(comparison.as_array).to eq [
        'Changed table: table1',
        'Changed chain: chain1',
        '-1: -A chain1 -p tcp -m tcp --dport 1 -j ACCEPT',
        '+1: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT',
      ]
    end
    it "should handle modified chain comments" do
      table2 = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
:chain2 ACCEPT [0:0]
-A chain2 -m comment --comment "changed comment2"
-A chain2 -p tcp -m tcp --dport 3 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 4 -j ACCEPT
COMMIT
        EOS
      ).tables['table1']
      comparison = IPTables::TableComparison.new(@table1, table2)

      comparison.include_comments
      expect(comparison.equal?).to be false

      comparison.ignore_comments
      expect(comparison.equal?).to be true
    end
  end
  describe 'chain comparison' do
    before :context do
      @table_text = <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
      EOS
      @table1_chain = IPTables::Tables.new( @table_text ).tables['table1'].chains['chain1']
    end
    it "should require valid IPTables::Chain object as a parameter" do
      expect { IPTables::ChainComparison.new nil, @table1_chain }.to raise_error RuntimeError
      expect { IPTables::ChainComparison.new @table1_chain, nil }.to raise_error RuntimeError
    end
    it "should evaluate chains with the same rules and policies as equal" do
      table2_chain = IPTables::Tables.new( @table_text ).tables['table1'].chains['chain1']
      comparison = IPTables::ChainComparison.new @table1_chain, table2_chain
      expect(comparison.equal?).to be true
      expect(comparison.as_array).to eq []
    end
    it "should require chains to have the same name" do
      table2_chain = IPTables::Tables.new(
        <<-EOS
*table1
:chain2 ACCEPT [0:0]
-A chain2 -m comment --comment "comment1"
-A chain2 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain2 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
        EOS
      ).tables['table1'].chains['chain2']
      expect { IPTables::ChainComparison.new @table1_chain, table2_chain }.to raise_error RuntimeError
    end
    it "should handle comments" do
      table2_chain = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "differing comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
        EOS
      ).tables['table1'].chains['chain1']
      comparison = IPTables::ChainComparison.new @table1_chain, table2_chain

      comparison.ignore_comments
      expect(comparison.equal?).to be true

      comparison.include_comments
      expect(comparison.equal?).to be false
      expect(comparison.missing).to eq({0=>'-A chain1 -m comment --comment "comment1"'})
      expect(comparison.new).to eq({0=>'-A chain1 -m comment --comment "differing comment1"'})
      expect(comparison.as_array).to eq [
        'Changed chain: chain1',
        '-0: -A chain1 -m comment --comment "comment1"',
        '+0: -A chain1 -m comment --comment "differing comment1"',
      ]
    end
    it "should show missing rules" do
      table2_chain = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
COMMIT
        EOS
      ).tables['table1'].chains['chain1']
      comparison = IPTables::ChainComparison.new @table1_chain, table2_chain

      expect(comparison.missing).to eq({2=>'-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT'})
      expect(comparison.as_array).to eq [
        'Changed chain: chain1',
        '-2: -A chain1 -p tcp -m tcp --dport 2 -j ACCEPT'
      ]
    end
    it "should show additional rules" do
      table2_chain = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 12 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
        EOS
      ).tables['table1'].chains['chain1']
      comparison = IPTables::ChainComparison.new @table1_chain, table2_chain

      expect(comparison.new).to eq({
        2=>'-A chain1 -p tcp -m tcp --dport 11 -j ACCEPT',
        3=>'-A chain1 -p tcp -m tcp --dport 12 -j ACCEPT'
      })
      expect(comparison.as_array).to eq [
        'Changed chain: chain1',
        '+2: -A chain1 -p tcp -m tcp --dport 11 -j ACCEPT',
        '+3: -A chain1 -p tcp -m tcp --dport 12 -j ACCEPT'
      ]
    end
    it "should show a changed policy" do
      table2_chain = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 REJECT [0:0]
-A chain1 -m comment --comment "comment1"
-A chain1 -p tcp -m tcp --dport 1 -j ACCEPT
-A chain1 -p tcp -m tcp --dport 2 -j ACCEPT
COMMIT
        EOS
      ).tables['table1'].chains['chain1']
      comparison = IPTables::ChainComparison.new @table1_chain, table2_chain

      expect(comparison.new_policy?).to be true
      expect(comparison.as_array).to eq [
        'Changed chain: chain1',
        'New policy: REJECT'
      ]
    end
  end
end


