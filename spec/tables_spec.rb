require "spec_helper"

describe IPTables do
  describe "#new" do
    before :example do
      @test_tables = IPTables::Tables.new({
        'table1' => {},
        'table2' => nil
      })
    end
    it "should take iptables input and return an IPTables object" do
      expect(@test_tables.tables['table1']).to be_an_instance_of IPTables::Table
    end
    it "should not make a table from nil" do
      expect(@test_tables.tables['table2']).to be_nil
    end
    it "should make a table from iptables-save output" do
      test_iptables = IPTables::Tables.new(
        "*table1\n*table2\nCOMMIT"
      )
      expect(test_iptables.tables['table1']).to be_an_instance_of IPTables::Table
      expect(test_iptables.tables['table2']).to be_an_instance_of IPTables::Table
    end
    it "should not make a table from bad string input" do
      expect { IPTables::Tables.new( 'garbage' ) }.to raise_error
    end
    it "should allow empty lines when parsing" do
      test_iptables = IPTables::Tables.new(
        <<-EOS
*table1
COMMIT

*table2
COMMIT
        EOS
      )
      expect(test_iptables.tables['table1']).to be_an_instance_of IPTables::Table
      expect(test_iptables.tables['table2']).to be_an_instance_of IPTables::Table
    end
  end


  describe 'array representation' do
    it "should not populate as_array with a nil table" do
      test_iptables = IPTables::Tables.new({'not' => nil})
      expect(test_iptables.as_array).to eq []
    end
    it "should ignore comments when comments = false" do
      config = IPTables::Configuration.new
      test_iptables = IPTables::Tables.new({
        'filter' => {
          'INPUT' => {
            'policy' => 'ACCEPT',
            'rules' => [
              { 'comment' => 'foobar' }
            ]
          }
        }
      }, config)
      expected_output = [
        "*filter",
        ":INPUT ACCEPT",
        "COMMIT"
      ]
      expect(test_iptables.as_array(false)).to eq expected_output
    end
    it "should produce consistent array output for multiple tables" do
      test_iptables = IPTables::Tables.new({
        'nat' => {
          'INPUT' => {
            'policy' => 'ACCEPT'
          }
        },
        'filter' => {
          'INPUT' => {
            'policy' => 'ACCEPT'
          }
        }
      })
      expected_output = [
        "*filter",
        ":INPUT ACCEPT",
        "COMMIT",
        "*nat",
        ":INPUT ACCEPT",
        "COMMIT"
      ]
      expect(test_iptables.as_array).to eq expected_output
    end
  end


  describe '#merge' do
    it "should return the original table when merged with a nil table" do
      test_iptables1 = IPTables::Tables.new({
        'table1' => nil
      })
      test_iptables2 = IPTables::Tables.new({
        'table1' => {
          'INPUT' => {
            'policy' => 'ACCEPT'
          }
        }
      })
      test_iptables1.merge(test_iptables2)
      expect(test_iptables1.tables['table1']).to be_an_instance_of IPTables::Table
      expected_output = [
        "*table1",
        ":INPUT ACCEPT",
        "COMMIT"
      ]
      expect(test_iptables1.as_array).to eq expected_output
    end
  end


  describe 'chains module' do
    before :context do
      @test_iptables = IPTables::Tables.new(
        <<-EOS
*table1
:chain1 ACCEPT [0:0]
-A chain1 -m comment --comment "BEGIN: in-bound traffic"
-A chain1 -j ACCEPT
COMMIT
        EOS
      )
      @chain1 = @test_iptables.tables['table1'].chains['chain1']
    end
    it "should have ACCEPT output policy" do
      expect(@chain1.output_policy).to eq 'ACCEPT'
    end
    it "should generate a correct array" do
      expected_output = [
        '-A chain1 -m comment --comment "BEGIN: in-bound traffic"',
        '-A chain1 -j ACCEPT'
      ]
      expect(@chain1.as_array).to eq expected_output
    end
    it "should generate an array without comments" do
      expect(@chain1.rules[0].type).to eq 'comment'
      expected_output = [
        '-A chain1 -j ACCEPT'
      ]
      expect(@chain1.as_array false).to eq expected_output
    end
    it "should build a correct path to the chain" do
      expect(@chain1.path).to eq 'table1.chain1'
    end
    it "should say that it is complete" do
      expect(@chain1.complete?).to eq true
    end
  end


  describe 'rules module' do
    before :context do
      @test_iptables = IPTables::Tables.new({
        'table1' => {
          'chain1' => {
            'policy' => 'ACCEPT',
            'rules' => [
              '-j ACCEPT'
            ]
          }
        }
      })
      @chain1 = @test_iptables.tables['table1'].chains['chain1']
    end
    it "should create a new rule" do
      expect(@chain1.rules[0].position).to eq 0
      expect( IPTables::Rule.new( {'raw' => '-j ACCEPT'}, @chain1 ).as_array ).to eq ['-A chain1 -j ACCEPT']
    end
    it "should parse a rule from text" do
      rule = IPTables::Rule.new( '-m comment --comment "BEGIN: in-bound traffic"', @chain1)
      expect(rule.rule_hash).to eq({'comment' => 'BEGIN: in-bound traffic'})
    end
    it "should handle a comment" do
      rule = IPTables::Rule.new( '-m comment --comment "BEGIN: in-bound traffic"', @chain1)
      expect(rule.type).to eq 'comment'
    end
    it "should ignore comments" do
      rule = IPTables::Rule.new( '-m comment --comment "BEGIN: in-bound traffic"', @chain1)
      expect(rule.as_array false).to eq []
    end
    it "should raise an error on a bad rule" do
      expect { IPTables::Rule.new( 1, @chain1 ) }.to raise_error
      # expect { IPTables::Rule.new( 'garbage' , @chain1 ) }.to raise_error
    end
    it "should build a correct path to the rule" do
      expect(@chain1.rules[0].path).to eq 'table1.chain1.0'
    end
  end
end
