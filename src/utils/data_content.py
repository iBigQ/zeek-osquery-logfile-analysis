import gzip
from pathlib import Path
import datetime

def iterate_log_lines(log_folder, dir_name, file_name):
    path = Path(log_folder) / dir_name / file_name
    with gzip.open(str(path), "rt") as f:
        for line in f:
            yield line

def iterate_logs(log_folder, log_files, log_date=None, orig_name=None):
    # Find log date
    for (log_d, dir_name) in sorted(log_files, key=lambda x:x[0]):
        if log_date and log_d != log_date: continue
        
        # Find file name
        for orig_n in sorted(log_files[(log_d, dir_name)]):
            if orig_name and orig_n != orig_name: continue
            
            # Find times
            for (from_datetime, to_datetime, file_name) in log_files[(log_d, dir_name)][orig_n]:
                from_dt = datetime.datetime.combine(log_d, from_datetime).replace(tzinfo=datetime.timezone.utc)
                to_dt = datetime.datetime.combine(log_d, to_datetime).replace(tzinfo=datetime.timezone.utc)
                yield dir_name, file_name, orig_n, from_dt, to_dt, iterate_log_lines(log_folder, dir_name, file_name)