class HostState():
    
    def __init__(self, start_date, end_date):
        # Experiment
        self.start_date = start_date
        self.end_date = end_date
        self.started = False
        
        # Metrics
        self.host_state = dict()
        
    def signal_start(self, ts):
        self.started = True
    
    def signal_restart(self, ts):
        # Force remove any remaining state
        self.host_state = dict()
    
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # osq-process_connections.log
        assert orig_name in ("osq-process-state", "osq-socket-state", "osq-user-state", "osq-interface-state")
        state_name = orig_name.split("-")[1]
        
        # Skip until started
        if not self.started: return
        
        # Headers
        sep = None
        col_idx = dict()
        
        # Iterate lines
        c = 0
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
                host_idx = col_idx["host"]
                added_idx = col_idx["added"]
                                
            # Skip header
            if line.startswith('#'): continue
            
            # Parse row
            row = line.split(sep)
            host = row[host_idx]
            added = row[added_idx]

            assert added in ("T", "F")
            if added != "T": continue
            c += 1

        if state_name not in self.host_state:
            self.host_state[state_name] = c
        else: self.host_state[state_name] += c

    
    def process_end(self, handlers):
        return
    
    def format_results(self):
        s = "State Sizes:"
        for state_name in sorted(self.host_state):
            s += "\tEntries for {}: {}\n".format(state_name, self.host_state[state_name])
            del self.host_state[state_name]
        return s
