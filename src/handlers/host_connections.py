class HostConnections():
    
    def __init__(self, start_date, end_date):
        # Experiment
        self.start_date = start_date
        self.end_date = end_date
        self.started = False
        
        # Metrics
        self.host_conns = dict()
        self.binary_counter = dict()
        
    def signal_start(self, ts):
        self.started = True
    
    def signal_restart(self, ts):
        # Force remove any remaining state
        self.host_conns = dict()
    
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # osq-process_connections.log
        assert orig_name == "osq-process_connections"
        
        # Skip until started
        if not self.started: return
        
        # Headers
        sep = None
        col_idx = dict()
        
        # Iterate lines
        for line in lines:
            line.rstrip()
                        
            # Column separator
            if line.startswith('#separator'):
                sep = "{}".format(line[len("#separator"):].strip())
                sep = "\x09"
                pass
            
            # Column names
            if line.startswith('#fields'):
                assert sep
                col_names = [r.strip() for r in line[len("#fields" + sep):].split(sep)]
                col_idx = {n:idx for idx, n in enumerate(col_names)}
                
                # Row indexes
                host_idx = col_idx["host"]
                added_idx = col_idx["added"]
                pid_idx = col_idx["pid"]
                binary_path_idx = col_idx["binary_path"]
                fd_idx = col_idx["fd"]
                state_idx = col_idx["state"]
                local_ip_idx = col_idx["local_addr"]
                local_port_idx = col_idx["local_port"]
                remote_ip_idx = col_idx["remote_addr"]
                remote_port_idx = col_idx["remote_port"]
                protocol_idx = col_idx["protocol"]
                                
            # Skip header
            if line.startswith('#'): continue
            
            # Parse row
            row = line.split(sep)
            host = row[host_idx]
            added = row[added_idx]
            pid = row[pid_idx]
            binary_path = row[binary_path_idx]
            fd = row[fd_idx]
            state = row[state_idx]
            local_ip = row[local_ip_idx]
            local_port = row[local_port_idx]
            remote_ip = row[remote_ip_idx]
            remote_port = row[remote_port_idx]
            protocol = row[protocol_idx]
            
            # Key and value
            entry = (host, pid, fd)
            value = (binary_path, state, local_ip, local_port, remote_ip, remote_port, protocol)

            # Remove entry
            if added != "T": 
                self.host_conns[entry].remove(value)
                continue
            
            if entry not in self.host_conns:
                self.host_conns[entry] = list()
            
            # Match existing connections
            exists = False
            for (ex_binary_path, ex_state, 
                 ex_local_ip, ex_local_port, ex_remote_ip, ex_remote_port, 
                 ex_protocol) in self.host_conns[entry]:
                
                # New binary
                if ex_binary_path != binary_path:
                    exists = True
                    break
                
                # Different remote
                if state == "established":
                    if (ex_state == "connect" and
                        ex_remote_ip == remote_ip and ex_remote_port == remote_port):
                        exists = True
                        break
                elif state == "connect":
                    if (ex_state == "established" and
                        ex_remote_ip == remote_ip and ex_remote_port == remote_port):
                        exists = True
                        break
                elif state == "listening":
                    if (ex_state == "bind" and
                        ex_remote_port not in (-1,0) and ex_remote_port == remote_port):
                        exists = True
                        break
                elif state == "bind":
                    if (ex_state == "listening" and
                        ex_remote_port not in (-1,0) and ex_remote_port == remote_port):
                        exists = True
                        break
                else:
                    raise RuntimeError("Unknown State {} for Host Connections".format(state))
                
            self.host_conns[entry].append(value)
                
            # New connection
            if not exists:
                if binary_path in self.binary_counter:
                    self.binary_counter[binary_path] += 1
                else:
                    self.binary_counter[binary_path] = 1
    
    def process_end(self, handlers):
        return
    
    def format_results(self):
        s = ""
        s += "Top 10 Binaries for host connections: {}".format(
            sorted(self.binary_counter.items(), key=lambda x:x[1], reverse=True)[:10]
            )
        
        return s