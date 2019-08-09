class Software():
    
    def __init__(self, start_date, end_date):
        # Experiment
        self.start_date = start_date
        self.end_date = end_date
        self.started = False
        
        # Metrics
        self.software = dict()
        self.versions = dict()
        
    def signal_start(self, ts):
        self.started = True
    
    def signal_restart(self, ts):
        return
    
    def process_log(self, orig_name, log_name, from_dt, to_dt, lines):
        # software.log
        assert orig_name == "software"
        
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
                name_idx = col_idx["name"]
                version_idx = col_idx["unparsed_version"]
                                
            # Skip header
            if line.startswith('#'): continue
            
            # Parse row
            row = line.split(sep)
            name = row[name_idx]
            version = row[version_idx]
            
            if name in self.software:
                self.software[name] += 1
            else:
                self.software[name] = 1
                
            if version in self.versions:
                self.versions[version] += 1
            else:
                self.versions[version] = 1
    
    def process_end(self, handlers):
        return
    
    def format_results(self):
        s = ""
#        s += "Top 10 software: {}".format(
#            sorted(self.software.items(), key=lambda x:x[1], reverse=True)[:10]
#            ) + "\n"
#        s += "Top 10 versions: {}".format(
#            sorted(self.versions.items(), key=lambda x:x[1], reverse=True)[:10]
#            )
        s += "Top software:\n"
        total = sum(self.software.values())
        print("Total {}".format(total))
        i = 1
        for e in sorted(self.software.items(), key=lambda x:x[1], reverse=True):
            s += "{}\t{} ({:3.2f}%)\n".format(i, e, e[1]/total*100)
            i += 1
        s += "Top 10 versions:\n"
        i = 1
        for e in sorted(self.versions.items(), key=lambda x:x[1], reverse=True):
            s += "{}\t{}\n".format(i, e)
            i += 1

        return s
