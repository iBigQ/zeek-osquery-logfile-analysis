import sys
import datetime

class OsqueryAddrs():
    
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
        for host in self.osquery_connects:
            # Only connects
            if host not in self.osquery_disconnects:
                continue
            
            # Currently offline
            if len(self.osquery_connects[host]) == len(self.osquery_disconnects[host]):
                del self.osquery_connects[host]
                del self.osquery_disconnects[host]
                
            # Cleanup
            self.osquery_connects[host] = self.osquery_connects[host][len(self.osquery_disconnects[host]):]
            self.osquery_disconnects[host] = list()
    
    def signal_restart(self, ts):
        # Force close peerings
        for host in self.osquery_connects:
            # Fill up disconnects to the same among as of connects
            
            # Only connects
            if host not in self.osquery_disconnects:
                last_ts = self.last_to_dt if self.last_to_dt else ts
                self.osquery_disconnects[host] = [last_ts] * len(self.osquery_connects[host])
            
            # Still alive
            if len(self.osquery_connects[host]) != len(self.osquery_disconnects[host]):
                self.osquery_disconnects[host] += [last_ts] * (len(self.osquery_connects[host]) - self.osquery_disconnects[host])
    
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # osq-interfaces.log
        assert orig_name == "osq-interfaces"
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
                
                # Fields
                ts_idx = col_idx["t"]
                host_idx = col_idx["host"]
                interface_idx = col_idx["interface"]
                mac_idx = col_idx["mac"]
                ip_idx = col_idx["ip"]
                mask_idx = col_idx["mask"]
            
            # Skip header
            if line.startswith('#'): continue
            
            # Row
            row = line.split(sep)

            # Values        
            ts = row[ts_idx]
            host_id = row[host_idx]
            interface = row[interface_idx]
            mac = row[mac_idx]
            ip = row[ip_idx]
            mask = row[mask_idx]
            
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
        return
    
    def format_results(self):
        s = ""
        s += "Unique Osquery Hosts: {}".format(len(self.osquery_connects))
        return s
    