require 'iptables/logger'

module IPTables
  class Tables
    # The main iptables object, encompassing all tables, their chains, their rules, etc
    attr_reader :config, :tables

    # Example: *filter
    @@parse_table_regex = /^\*(\S+)$/
    # Example: # Generated by iptables-save v1.4.4 on Wed Sep 26 18:38:44 2012
    @@parse_comment_regex = /^#/

    def initialize(input, config=nil)
      @config = config
      $log.debug('init IPTables')
      @tables = Hash.new

      case input
      when Hash
        input.keys.sort.each{ |table_name|
          table_info = input[table_name]
          case table_info
          when nil, false
            @tables[table_name] = table_info
            next
          end
          table = Table.new(table_name, self, table_info)
          @tables[table_name] = table
        }

      when String
        self.parse(input.split(/\n/))

      else
        raise "don't know how to handle input: #{input.inspect}"
      end
    end

    def as_array(comments = true)
      array = []
      $log.debug('IPTables array')
      @tables.keys.sort.each{ |name|
        table = @tables[name]
        $log.debug("#{name}: #{table}")
        next if table.nil?
        array << '*'+name
        array += table.as_array(comments)
        array << 'COMMIT'
      }
      return array
    end

    def merge(merged)
      raise "must merge another IPTables::Tables" unless merged.class == IPTables::Tables
      merged.tables.each{ |table_name, table_object|
        $log.debug("merging table #{table_name}")

        case table_object
        when false
          $log.debug("deleting table #{table_name}")
          @tables.delete(table_name)
          next

        when nil
          next
        end

        # only a Table is expected from here onwards

        # merged table
        if (@tables.has_key? table_name) and not (@tables[table_name].nil?)
          @tables[table_name].merge(table_object)
          next
        end

        # new table
        @tables[table_name] = table_object
      }

      # find and apply any node rule addition points
      @tables.each{ |name, table|
        next unless table.class == IPTables::Table
        $log.debug("applying additions to table #{name}")
        table.apply_additions(merged)
      }
    end

    def get_node_additions(table_name, chain_name)
      $log.debug("finding additions for table #{table_name}, chain #{chain_name}")
      return unless @tables.has_key? table_name
      return unless @tables[table_name].class == IPTables::Table
      return @tables[table_name].get_node_additions(chain_name)
    end

    def parse(lines)
      position = 0
      while position < lines.length
        line = lines[position]
        #$log.debug(line)
        position += 1

        case line
        when ""
          # ignore empty lines
        when @@parse_comment_regex, 'COMMIT'
          # ignored
        when @@parse_table_regex
          @tables[$1] = IPTables::Table.new($1, self)
          position += @tables[$1].parse(lines[position .. -1])
        else
          raise "unhandled line: #{line}"
        end
      end
      raise 'no tables found' unless @tables.any?
    end
  end

  class TablesComparison
    def initialize(tables1, tables2)
      raise "must provide two tables" unless (tables1.class == IPTables::Tables) and (tables2.class == IPTables::Tables)
      @tables1 = tables1
      @tables2 = tables2
      @table_diffs = []

      @including_comments = true
      @compared = false
    end

    def compare
      return if @compared
      @equal = true

      tables1_tables = @tables1.tables.keys.sort
      tables2_tables = @tables2.tables.keys.sort
      @only_in_current = (tables1_tables - tables2_tables).reject{ |t| @tables1.tables[t].nil? }
      @only_in_new = (tables2_tables - tables1_tables).reject{ |t| @tables2.tables[t].nil? }
      @equal = false if @only_in_current.any? or @only_in_new.any?

      @table_diffs = []
      (tables1_tables - @only_in_current - @only_in_new).each{ |table|
        table1 = @tables1.tables[table]
        table2 = @tables2.tables[table]

        # nil tables are only created by policy, never parsed
        # they mean "use the parsed policy here"
        # which means "for comparison purposes, they are always equal"
        next if table1.nil? or table2.nil?

        table_comparison = IPTables::TableComparison.new(table1, table2)
        if @including_comments
          table_comparison.include_comments
        else
          table_comparison.ignore_comments
        end
        next if table_comparison.equal?

        @equal = false
        @table_diffs << table_comparison
      }

      return nil
    end

    def ignore_comments
      @including_comments = false
      @compared = false
    end

    def include_comments
      @including_comments = true
      @compared = false
    end

    def equal?
      self.compare
      return @equal
    end

    def as_array
      self.compare
      array = []
      return array if self.equal?
      if @only_in_current.any?
        @only_in_current.each{ |table_name|
          array << "Missing table: #{table_name}"
          array.concat @tables1.tables[table_name].as_array
        }
      end
      if @only_in_new.any?
        @only_in_new.each{ |table_name|
          array << "New table: #{table_name}"
          next if @tables2.tables[table_name].nil?
          array.concat @tables2.tables[table_name].as_array
        }
      end
      if @table_diffs.any?
        @table_diffs.each{ |table_comparison|
          array.concat table_comparison.as_array
        }
      end
      return array
    end
  end

  class Table
    # standard tables: nat, mangle, raw, filter
    attr_reader :chains, :name, :node_addition_points, :my_iptables

    # Example: :INPUT DROP [0:0]
    @@chain_policy_regex = /^:(\S+)\s+(\S+)\s+/
    # Example: -A INPUT -m comment --comment "BEGIN: in-bound traffic"
    @@chain_rule_regex = /^-A\s+(\S+)\s+(.+)/

    def initialize(name, my_iptables, table_info_hash={})
      @name = name
      @my_iptables = my_iptables
      $log.debug("init Table #{@name}")

      @node_addition_points = {}
      @chains = {}

      table_info_hash.keys.sort.each{ |chain_name|
        chain_info = table_info_hash[chain_name]
        case chain_info
        when Hash
          @chains[chain_name] = IPTables::Chain.new(chain_name, chain_info, self)

        when false, nil
          @chains[chain_name] = chain_info

        else
          raise "don't know how to handle #{chain_name}: #{chain_info.inspect}"
        end
      }
      $log.debug("table #{@name} is #{self}")
    end

    def as_array(comments = true)
      policies = []
      chains = []

      # special sorting rule INPUT FORWARD OUTPUT are always first, in this order
      chain_order = @chains.keys.sort()
      %w/INPUT FORWARD OUTPUT/.reverse.each{ |chain|
        next unless chain_order.include? chain
        chain_order -= [chain]
        chain_order.unshift(chain)
      }
      $log.debug("chain order: #{chain_order.inspect}")

      chain_order.each{ |name|
        $log.debug("chain #{name}")
        chain = @chains[name]
        policies.push ":#{name} #{chain.output_policy}"
        chains += chain.as_array(comments)
      }
      return policies + chains
    end

    def path()
      @name
    end

    def merge(table_object)
      table_object.chains.each{ |chain_name, chain_object|
        $log.debug("merging chain #{chain_name}")

        case chain_object
        when false
          @chains.delete(chain_name)
          next

        when nil
          next
        end
        # only a Chain is expected from here onwards

        # merge Chain
        if @chains.has_key? chain_name
          @chains[chain_name].merge(chain_object)
          next
        end

        # copy Chain
        @chains[chain_name] = chain_object if chain_object.complete?
      }
    end

    def apply_additions(other_firewall)
      $log.debug("node addition points: #{@node_addition_points.inspect}")
      @chains.each{ |name, chain_object|
        $log.debug("looking for additions to chain #{name}")
        next unless @node_addition_points.has_key? name
        chain_object.apply_additions(other_firewall)
      }
    end

    def register_node_addition_point(addition_name)
      $log.debug("registering node addition point for #{addition_name}")
      @node_addition_points[addition_name] = true
    end

    def get_node_additions(chain_name)
      return unless @chains.has_key? chain_name
      return @chains[chain_name].get_node_additions
    end

    def parse(lines)
      position = 0
      while position < lines.length
        line = lines[position]
        position += 1

        case line
        when @@chain_policy_regex
          @chains[$1] = IPTables::Chain.new($1, {'policy' => $2}, self)
        when @@chain_rule_regex
          raise "unrecognized chain: #{$1}" unless @chains.has_key? $1
          @chains[$1].parse_rule($2)
        else
          $log.debug("returning on unrecognized line: #{line}")
          # back up a line
          return position - 1
        end
      end
    end
  end

  class TableComparison
    def initialize(table1, table2)
      raise "must provide two tables" unless (table1.class == IPTables::Table) and (table2.class == IPTables::Table)
      raise "table names should match" unless table1.name == table2.name
      @table1 = table1
      @table2 = table2

      @including_comments = true
      @compared = false
    end

    def compare
      return if @compared
      @equal = true

      table1_chains = @table1.chains.keys.sort
      table2_chains = @table2.chains.keys.sort
      @only_in_current = table1_chains - table2_chains
      @only_in_new = table2_chains - table1_chains
      @equal = false if @only_in_current.any? or @only_in_new.any?

      @chain_diffs = []
      (table1_chains - @only_in_current - @only_in_new).each{ |chain|
        chain_comparison = IPTables::ChainComparison.new(@table1.chains[chain], @table2.chains[chain])
        if @including_comments
          chain_comparison.include_comments
        else
          chain_comparison.ignore_comments
        end
        next if chain_comparison.equal?

        @equal = false
        @chain_diffs << chain_comparison
      }

      return nil
    end

    def ignore_comments
      @including_comments = false
      @compared = false
    end

    def include_comments
      @including_comments = true
      @compared = false
    end

    def missing
      self.compare
      return @only_in_current
    end

    def new
      self.compare
      return @only_in_new
    end

    def changed
      self.compare
      return @chain_diffs
    end

    def as_array
      self.compare
      array = []
      return array if self.equal?
      array << "Changed table: #{@table1.name}"
      if self.missing.any?
        self.missing.each{ |chain_name|
          array << 'Missing chain:'
          array.concat @table1.chains[chain_name].all_as_array
        }
      end
      if self.new.any?
        self.new.each{ |chain_name|
          array << 'New chain:'
          array.concat @table2.chains[chain_name].all_as_array
        }
      end
      if self.changed.any?
        self.changed.each{ |chain_comparison|
          array.concat chain_comparison.as_array
        }
      end
      return array
    end

    def equal?
      self.compare
      return @equal
    end
  end

  class Chain
    # example chain names in filter table: INPUT, FORWARD, OUTPUT
    attr_reader :additions, :name, :node_addition_points, :my_table, :policy, :rules

    def initialize(name, chain_info_hash, my_table)
      @name = name
      @chain_info_hash = chain_info_hash
      @my_table = my_table

      $log.debug("init Chain #{@name}")
      @node_addition_points = []

      @policy = @chain_info_hash['policy']
      @rules = self.find_and_add_type('rules')
      @additions = self.find_and_add_type('additions')
    end

    def find_and_add_type(data_type)
      rules = []
      return unless @chain_info_hash.has_key? data_type
      @chain_info_hash[data_type].each_with_index{ |rule, index|
        rule_object = IPTables::Rule.new(rule, self)
        rule_object.set_position(index)
        rules.push(rule_object)
      }
      return rules
    end

    def output_policy()
      return (@policy == nil) ? '-' : @policy
    end

    def as_array(comments = true)
      $log.debug("Chain #{@name} array")
      return [] if @rules == nil
      rules = @rules.collect{ |rule| rule.as_array(comments)}.flatten
      $log.debug(rules)
      return rules
    end

    def all_as_array(comments = true)
      return [
        ":#{@name} #{self.output_policy}",
        self.as_array
      ].flatten
    end

    def merge(chain_object)
      # if found, replace policy
      @policy = chain_object.policy unless chain_object.policy.nil?

      # if found, replace rules
      @rules = chain_object.rules unless chain_object.rules.nil?
    end

    def path()
      @my_table.path + ".#{@name}"
    end

    def register_node_addition_point(rule_object, addition_name)
      @node_addition_points.push(rule_object) unless @node_addition_points.include? rule_object
      @my_table.register_node_addition_point(addition_name)
    end

    def get_node_additions()
      return if @additions.empty?
      return @additions
    end

    def apply_additions(other_firewall)
      @node_addition_points.each{ |rule_object|
        $log.debug("applying additions for #{rule_object.path}")
        rule_object.apply_additions(other_firewall)
      }
    end

    def parse_rule(args)
      @rules = [] if @rules.nil?
      # parsed rules come with trailing whitespace; remove
      rule_object = IPTables::Rule.new(args.strip, self)
      rule_object.set_position(@rules.length)
      @rules.push(rule_object)
    end

    def complete?
      if @rules.nil?
        return true if @additions.nil?
        return false
      end
      return true if @rules.any?
    end
  end

  class ChainComparison
    require 'diff/lcs'

    def initialize(chain1, chain2)
      raise "must provide two chains" unless (chain1.class == IPTables::Chain) and (chain2.class == IPTables::Chain)
      raise "first and second chain should have same name" unless chain1.name == chain2.name
      @chain1 = chain1
      @chain2 = chain2

      @including_comments = true
      @compared = false
    end

    def ignore_comments
      @including_comments = false
      @compared = false
    end

    def include_comments
      @including_comments = true
      @compared = false
    end

    def compare
      return if @compared

      @equal = true

      @missing_rules = {}
      @new_rules = {}
      Diff::LCS.diff(
        @chain1.as_array(@including_comments),
        @chain2.as_array(@including_comments)
      ).each{ |diffgroup|
        diffgroup.each{ |diff|
          if diff.action == '-'
            @missing_rules[diff.position] = diff.element
          else
            @new_rules[diff.position] = diff.element
          end
          @equal = false
        }
      }

      @new_policy = false
      unless @chain1.policy == @chain2.policy
        @new_policy = true
        @equal = false
      end

      @compared = true
      return nil
    end

    def equal?
      self.compare
      return @equal
    end

    def missing
      self.compare
      return @missing_rules
    end

    def new
      self.compare
      return @new_rules
    end

    def as_array
      self.compare
      array = []
      return array if self.equal?
      array << "Changed chain: #{@chain1.name}"
      array << "New policy: #{@chain2.policy}" if self.new_policy?
      if self.missing.any?
        self.missing.keys.sort.each{ |rule_num|
          array << "-#{rule_num}: #{self.missing[rule_num]}"
        }
      end
      if self.new.any?
        self.new.keys.sort.each{ |rule_num|
          array << "+#{rule_num}: #{self.new[rule_num]}"
        }
      end
      return array
    end

    def new_policy?
      self.compare
      return @new_policy
    end
  end

  class Rule
    # possible key names for custom named tcp and/or udp services
    @@valid_custom_service_keys = %w/service_name service_udp service_tcp/
    attr_reader :position, :rule_hash, :type

    @@parse_comment_regex = /^\-m\s+comment\s+\-\-comment\s+"([^"]+)"/

    def initialize(rule_info, my_chain)
      $log.debug("received Rule info #{rule_info.inspect}")

      @rule_info = rule_info
      case rule_info
      when String
        self.handle_string(rule_info)
      when Hash
        @rule_hash = rule_info
      else
        raise "don't know how to handle rule_info: #{rule_info.inspect}"
      end

      @my_chain = my_chain

      @position = nil

      # expanded rules will use this instead of @args
      @children = []

      @args = ''

      self.handle_requires_primitive

      case @rule_hash.length
      when 1
        @type = @rule_hash.keys.first
      when 2, 3
        @type = 'custom_service'
      else
        raise 'do not know how to handle this rule'
      end

      $log.debug("create Rule #{@type}")

      case @type
      when 'comment'

      when 'custom_service'
        self.handle_custom_service()

      when 'empty'

      when 'interpolated'
        self.handle_interpolated()

      when 'macro'
        self.handle_macro()

      when 'node_addition_points'
        self.handle_node_addition_points()

      when 'raw'

      when 'service'
        self.handle_service()

      when 'service_tcp'

      when 'service_udp'

      when 'ulog'

      else
        raise "unrecognized rule type #{@type}"
      end
    end

    def add_child(rule_hash)
      @children.push(IPTables::Rule.new(rule_hash, @my_chain))
    end

    def handle_requires_primitive
      @requires_primitive = nil
      return unless @rule_hash.has_key? 'requires_primitive'
      @requires_primitive = @rule_hash['requires_primitive']
      @rule_hash.delete('requires_primitive')
      config = @my_chain.my_table.my_iptables.config
      raise 'missing config' if config.nil?
      primitives = config.primitives
      raise 'missing primitives' if primitives.nil?
      @rule_hash = {'empty' => nil} unless primitives.has_primitive?(@requires_primitive)
    end

    def handle_custom_service()
      raise "missing service name: #{@rule_hash.inspect}" unless @rule_hash.has_key? 'service_name'

      custom_service_port = nil
      custom_services = []
      @rule_hash.keys.sort.each{ |key|
        next if key == 'service_name'
        raise "unknown service key: #{key}" unless @@valid_custom_service_keys.include? key
        custom_services << {key => @rule_hash[key]}
        # set the custom service port if exactly one custom service has a port
        # or both services have the same port
        if custom_service_port.nil?
          custom_service_port = @rule_hash[key]
        else
          custom_service_port = nil unless @rule_hash[key].to_i == custom_service_port.to_i
        end
      }

      if custom_service_port.nil?
        self.add_child({'comment' => "_ #{@rule_hash['service_name']}"})
      else
        self.add_child({'comment' => "_ Port #{custom_service_port} - #{@rule_hash['service_name']}"})
      end
      custom_services.each{ |service_hash|
        self.add_child(service_hash)
      }
    end

    def handle_interpolated()
      config = @my_chain.my_table.my_iptables.config
      raise 'missing config' if config.nil?
      interpolations = config.interpolations
      $log.debug("interpolating: #{@rule_hash['interpolated']}")
      interpolations.children(@rule_hash['interpolated']).each{ |rule_hash|
        self.add_child(rule_hash)
      }
    end

    def handle_macro()
      config = @my_chain.my_table.my_iptables.config
      raise 'missing config' if config.nil?
      macro = config.macros.named[@rule_hash['macro']]
      $log.debug("macro: #{macro.name}")
      macro.children.each{ |rule_hash|
        self.add_child(rule_hash)
      }
    end

    def handle_node_addition_points()
      self.add_child({'empty' => nil})
      @rule_hash['node_addition_points'].each{ |addition_name|
        @my_chain.register_node_addition_point(self, addition_name)
      }
    end

    def handle_service()
      config = @my_chain.my_table.my_iptables.config
      raise 'missing config' if config.nil?
      service = config.services.named[@rule_hash['service']]
      $log.debug("service: #{service.name}")
      service.children.each{ |rule_hash|
        self.add_child(rule_hash)
      }
    end

    def handle_string(rule_info)
      # try to parse strings

      if rule_info =~ @@parse_comment_regex
        # if we're a comment, set as comment
        @rule_hash = {'comment' => $1}
      else
        # otherwise set as raw
        @rule_hash = {'raw' => rule_info}
      end
    end

    def as_array(comments = true)
      case @type
      when 'comment'
        return [] unless comments
        self.generate_comment()

      when 'empty'
        return []

      when 'raw'
        self.generate_raw()

      when 'service_tcp'
        self.generate_tcp()

      when 'service_udp'
        self.generate_udp()

      when 'ulog'
        self.generate_ulog()
      end

      if @children.empty?
        raise "@args is empty" unless @args.length > 0
        return ["-A #{@my_chain.name} #{@args}"]
      else
        rules = @children.collect{ |child| child.as_array(comments)}.flatten
        $log.debug(rules)
        return rules
      end
    end

    def generate_comment()
      @args = %Q|-m comment --comment "#{@rule_hash['comment']}"|
    end

    def generate_raw()
      @args = @rule_hash['raw']
    end

    def generate_tcp()
      @args = "-p tcp -m tcp --sport 1024:65535 --dport #{@rule_hash['service_tcp']} -m state --state NEW,ESTABLISHED -j ACCEPT"
    end

    def generate_udp()
      @args = "-p udp -m udp --sport 1024:65535 --dport #{@rule_hash['service_udp']} -m state --state NEW,ESTABLISHED -j ACCEPT"
    end

    def generate_ulog()
      @args = %Q|-m limit --limit 1/sec --limit-burst 2 -j ULOG --ulog-prefix "#{@my_chain.name}:"|

      if @rule_hash['ulog'] == '-p tcp'
        @args = "-p tcp #{@args}"
      end
    end

    def path()
      @my_chain.path + ".#{@position}"
    end

    def set_position(number)
      @position = number
    end

    def apply_additions(other_firewall)
      @rule_hash['node_addition_points'].each{ |addition_name|
        other_rules = other_firewall.get_node_additions(@my_chain.my_table.name, addition_name)
        next if other_rules.nil?
        $log.debug("applying additions at #{addition_name}")
        other_rules.each{ |other_rule_object|
          self.add_child(other_rule_object.rule_hash)
        }
      }
    end
  end
end
