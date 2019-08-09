import sys

class Connections():
    
    def __init__(self, start_date, end_date):
        # Experiment
        self.start_date = start_date
        self.end_date = end_date
        self.started = False
        
        # Metrics
        self.conns = 0
        self.established = 0
        self.local_intent = 0
        
        self.conns_host = 0
        self.attr_host = 0
        self.attr_host_unq = 0
        self.attr_host_dup = 0
        self.attr_pid = 0
        self.attr_pid_unq = 0
        self.attr_pid_unq_no_dns = 0
        self.attr_pid_dup = 0
        self.attr_uid = 0
        self.attr_uid_unq = 0
        self.attr_uid_dup = 0
        
    def signal_start(self, ts):
        self.started = True
    
    def signal_restart(self, ts):
        return
    
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # conn.log
        assert orig_name == "conn"
        skip_osquery = None
        
        # Skip until started
        if not self.started: return
        
        # Headers
        sep = None
        col_idx = dict()
        
        # Iterate lines
        for line in lines:
            line = line.rstrip()
                        
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
                conn_state_idx = col_idx["conn_state"]
                local_orig_idx = col_idx["local_orig"]
                orig_h_idx = col_idx["id.orig_h"]
                resp_p_idx = col_idx["id.resp_p"]
                #duration_idx = col_idx["duration"]
    
                # Row indexes for attribution
                osquery_names = set(["orig_hosts", "orig_pids", "orig_uids", "resp_hosts", "resp_pids", "resp_uids"])
                if osquery_names.intersection(set(col_idx)) == osquery_names:
                    orig_hosts_idx = col_idx["orig_hosts"]
                    orig_pids_idx = col_idx["orig_pids"]
                    orig_uids_idx = col_idx["orig_uids"]
                    resp_hosts_idx = col_idx["resp_hosts"]
                    resp_pids_idx = col_idx["resp_pids"]
                    resp_uids_idx = col_idx["resp_uids"]
                else:
                    print("No osquery fields in '{}'".format(log_name), file=sys.stderr)
                    skip_osquery = True
                                
            # Skip header
            if line.startswith('#'): continue

            # Parse row
            row = line.split(sep)
            conn_state = row[conn_state_idx]
            local_orig = row[local_orig_idx]
            orig_h = row[orig_h_idx]
            resp_p = row[resp_p_idx]
            #duration = row[duration_idx]

            # Connection Count
            self.conns += 1
            
            # Only when local is reacting
            # - Originated by local
            locally_intented = True if local_orig=="T" and orig_h=="134.100.15.53" else False
            # - Connection established
            conn_established = True if conn_state in ("S1", "SF", "S2", "S3", "RSTO", "RSTOS0", "OTH") else False
            if conn_established: self.established += 1
            if locally_intented or conn_established: self.local_intent += 1
            #elif conn_state not in ("S0", "REJ", "RSTOS0", "RSTRH", "SHR") or duration!="-":      
            
            # Attribution
            if skip_osquery: continue
            orig_hosts = row[orig_hosts_idx]
            resp_hosts = row[resp_hosts_idx]
            orig_pids = row[orig_pids_idx]
            resp_pids = row[resp_pids_idx]
            orig_uids = row[orig_uids_idx]
            resp_uids = row[resp_uids_idx]
            
            if orig_hosts != "-" or resp_hosts != "-":
                self.conns_host += 1
            
            # - Hosts
            if orig_hosts != "-":
                o_hosts = [s.strip() for s in orig_hosts.split(",")]
                self.attr_host += 1
                if len(o_hosts) == 1: self.attr_host_unq += 1
                self.attr_host_dup += len(o_hosts)
            if resp_hosts != "-":
                r_hosts = [s.strip() for s in resp_hosts.split(",")]
                self.attr_host += 1
                if len(r_hosts) == 1: self.attr_host_unq += 1
                self.attr_host_dup += len(r_hosts)
            # - Processes
            if orig_pids != "-":
                o_pids = [s.strip() for s in orig_pids.split(",")]
                self.attr_pid += 1
                if len(o_pids) == 1: self.attr_pid_unq += 1
                if len(o_pids) > 1 and resp_p == "53": self.attr_pid_unq_no_dns += 1
                self.attr_pid_dup += len(o_pids)
            if resp_pids != "-":
                r_pids = [s.strip() for s in resp_pids.split(",")]
                self.attr_pid += 1
                if len(r_pids) == 1: self.attr_pid_unq += 1
                self.attr_pid_dup += len(r_pids)
            # - Users
            if orig_uids != "-":
                o_uids = [s.strip() for s in orig_uids.split(",")]
                self.attr_uid += 1
                if len(o_uids) == 1: self.attr_uid_unq += 1
                self.attr_uid_dup += len(o_uids)
            if resp_uids != "-":
                r_uids = [s.strip() for s in resp_uids.split(",")]
                self.attr_uid += 1
                if len(r_uids) == 1: self.attr_uid_unq += 1
                self.attr_uid_dup += len(r_uids)
    
    def process_end(self, handlers):
        return
    
    def format_results(self):
        s = ""
        s += "Connections: {}".format(self.conns) + "\n"
        s += "Established Connections: {}".format(self.established) + "\n"
        s += "Connections With Local Intention: {}".format(self.local_intent) + "\n"
        s += "Connections With Attributed Hosts: {}".format(self.conns_host) + "\n"
        s += "Host Attributions: {}".format(self.attr_host) + "\n"
        s += "Unique Host Attributions: {}".format(self.attr_host_unq) + "\n"
        s += "Host Attribution Candidates: {}".format(self.attr_host_dup) + "\n"
        s += "Process Attributions: {}".format(self.attr_pid) + "\n"
        s += "Unique Process Attributions: {}".format(self.attr_pid_unq) + "\n"
        s += "Process Attribution Candidates: {}".format(self.attr_pid_dup) + "\n"
        s += "Duplicate Process Attributions To DNS: {}".format(self.attr_pid_unq_no_dns) + "\n"
        s += "User Attributions: {}".format(self.attr_uid) + "\n"
        s += "Unique User Attributions: {}".format(self.attr_uid_unq) + "\n"
        s += "User Attribution Candidates: {}".format(self.attr_uid_dup)
        
        return s
