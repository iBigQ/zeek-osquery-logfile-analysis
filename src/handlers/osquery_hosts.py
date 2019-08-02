import datetime

class OsqueryHosts():
    
    def __init__(self, start_date, end_date):
        # Experiment
        self.start_date = start_date
        self.end_date = end_date
        
        # Runtime
        self.started = False
        self.last_to_dt = None
        
        # Metrics
        self.osquery_connects = dict()
        self.osquery_disconnects = dict()
        
        
    def signal_start(self, ts):
        self.started = True
        # Only keep last online timestamp
        
        # Prune online hosts
        to_delete = list()
        for host in self.osquery_connects:
            # Only connects
            if host not in self.osquery_disconnects:
                continue
            
            # Currently offline
            if len(self.osquery_connects[host]) == len(self.osquery_disconnects[host]):
                #del self.osquery_connects[host]
                #del self.osquery_disconnects[host]
                to_delete.append(host)
                
            # Cleanup
            self.osquery_connects[host] = self.osquery_connects[host][len(self.osquery_disconnects[host]):]
            self.osquery_disconnects[host] = list()

        for host in to_delete:
            del self.osquery_connects[host]
            del self.osquery_disconnects[host]

    
    def signal_restart(self, ts):
        # Force close peerings
        for host in self.osquery_connects:
            # Fill up disconnects to the same among as of connects
            #last_ts = self.last_to_dt if self.last_to_dt else ts
            last_ts = ts
            
            # Only connects
            if host not in self.osquery_disconnects:
                self.osquery_disconnects[host] = [last_ts] * len(self.osquery_connects[host])
            
            # Still alive
            if len(self.osquery_connects[host]) != len(self.osquery_disconnects[host]):
                assert len(self.osquery_disconnects[host]) <= len(self.osquery_connects[host])
                self.osquery_disconnects[host] += [last_ts] * (len(self.osquery_connects[host]) - len(self.osquery_disconnects[host]))
                
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # conn.log
        assert orig_name == "osquery"
        self.last_to_dt = to_dt
        
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
                ts_idx = col_idx["ts"]
                #source_idx = col_idx["source"]
                peer_idx = col_idx["peer"]
                #level_idx = col_idx["level"]
                message_idx = col_idx["message"]
            
            # Skip header
            if line.startswith('#'): continue
            
            # Parse row
            row = line.split(sep)            
            ts = float(row[ts_idx])
            #source = row[source_idx]
            peer_id = row[peer_idx]
            #level = row[level_idx]
            message = row[message_idx]
            
            # Connects
            if (message.startswith("Osquery host connected")):
                if peer_id not in self.osquery_connects:
                    self.osquery_connects[peer_id] = list()
                self.osquery_connects[peer_id].append(datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=datetime.timezone.utc))
                
            # Disconnects
            if (message.startswith("Osquery host disconnected")):
                if peer_id not in self.osquery_disconnects:
                    self.osquery_disconnects[peer_id] = list()
                self.osquery_disconnects[peer_id].append(datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=datetime.timezone.utc))
            
    def process_end(self, handlers):
        self.candidates = list()
        self.online_hosts = dict()
        
        # Iterate hosts
        hosts = dict()
        for host in self.osquery_connects:
            
            # Online all time
            if host not in self.osquery_disconnects:
                continue
            
            # Strict ordering
            for (connect_ts, disconnect_ts) in zip(self.osquery_connects[host], self.osquery_disconnects[host]):
                assert connect_ts <= disconnect_ts
                
            # Balance
            if host in self.osquery_disconnects:
                assert (len(self.osquery_connects[host]) - len(self.osquery_disconnects[host])) in (0,1) 

            # Timestamps of host changes
            balance = 0
            for (ts, connected) in (sorted(
                [(t, True) for t in self.osquery_connects[host]] + 
                [(t, False) for t in self.osquery_disconnects[host]],
                key=lambda x:x[0])):

                # Next connect
                if connected:
                    balance += 1
                    # Update hosts
                    if balance == 1:
                        if ts in hosts:
                            hosts[ts].append([+1, host])
                        else:
                            hosts[ts] = [[+1, host]]
                # Next disconnect
                else:
                    balance -= 1
                    # Update hosts
                    assert balance >= 0
                    if balance == 0:
                        if ts in hosts:
                            hosts[ts].append([-1, host])
                        else:
                            hosts[ts] = [[-1, host]]
                
        # Build online host dictionary
        last_ts = None            
        for (ts, u_type, node_id) in sorted(
            [
                (ts, u_type, node_id) 
                for (ts, ts_entries) in hosts.items() for (u_type, node_id) in ts_entries
            ], key = lambda x:x[0]):
            
            # First timestamp
            if not last_ts:
                if u_type == 1:
                    self.online_hosts[ts] = set([node_id])
                else:
                    raise RuntimeError()
            # Following timestamps
            else:
                if u_type == 1:
                    self.online_hosts[ts] = set(self.online_hosts[last_ts])
                    self.online_hosts[ts].add(node_id)
                elif u_type == -1:
                    self.online_hosts[ts] = set(self.online_hosts[last_ts])
                    self.online_hosts[ts].remove(node_id)
                else:
                    raise RuntimeError()
            last_ts = ts
                
        # Build online host candidates
        for ts in self.online_hosts:
            self.candidates.append(ts)
        self.candidates = sorted(self.candidates)
            
    def get_online_hosts(self, ts):
        if ts < self.candidates[0]:
            return set()
        else: 
            select_t = max((t for t in self.candidates if t <= ts))
            return self.online_hosts[select_t]
            
    def format_results(self):
        s = ""
        s += "Unique Osquery Hosts: {}".format(len(self.osquery_connects))
        return s
    
