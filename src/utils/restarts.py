import gzip
import datetime
import json
from pathlib import Path

STDOUT = "stdout"
CLUSTER = "cluster"
RESTART_LINES_STDOUT = {
    0: "max memory size",
    1: "data seg size",
    2: "virtual memory",
    3: "core file size"
    }
RESTART_LINES_CLUSTER = {
    9: "created clone store"
    }

def iterate_restart_datetimes(log_folder, log_files, start_date=None, end_date=None):
    for (log_date, dir_name) in log_files:
        
        # Check date
        if start_date and log_date < start_date: continue
        if end_date and log_date > end_date: continue
        
        # Iterate stdout log files
        if STDOUT not in log_files[(log_date, dir_name)]: 
            print("Not stdout.log found")
            continue
        for (from_datetime, to_datetime, file_name) in log_files[(log_date, dir_name)][STDOUT]:
            # Read log file
            with gzip.open(str(log_folder / dir_name / file_name), "rt") as f:
                for (line_idx, line_str) in enumerate(f):
                    # Skip line
                    if line_idx not in RESTART_LINES_STDOUT: continue
                    # Check line
                    if not line_str.startswith(RESTART_LINES_STDOUT[line_idx]): break
                    # Restart detected
                    if line_idx >= max(RESTART_LINES_STDOUT):
                        restart_datetime = datetime.datetime.combine(log_date, from_datetime).replace(tzinfo=datetime.timezone.utc)
                        yield restart_datetime
                        break
                    
def iterate_restart_datetimes_cluster(log_folder, log_files, start_date=None, end_date=None):
    for (log_date, dir_name) in log_files:
        
        # Check date
        if start_date and log_date < start_date: continue
        if end_date and log_date > end_date: continue
        
        # Iterate stdout log files
        if CLUSTER not in log_files[(log_date, dir_name)]: continue
        for (from_datetime, to_datetime, file_name) in log_files[(log_date, dir_name)][CLUSTER]:
            # Read log file
            with gzip.open(str(log_folder / dir_name / file_name), "rt") as f:
                for (line_idx, line_str) in enumerate(f):
                    # Skip line
                    if line_idx not in RESTART_LINES_CLUSTER: continue
                    # Check line
                    if RESTART_LINES_CLUSTER[line_idx] not in line_str: break
                    # Restart detected
                    if line_idx >= max(RESTART_LINES_CLUSTER):
                        restart_datetime = datetime.datetime.combine(log_date, from_datetime).replace(tzinfo=datetime.timezone.utc)
                        yield restart_datetime
                        break
                    
def get_restart_datetimes(log_folder, log_files, start_date=None, end_date=None):
    # Retrieve restart datetimes
    restart_datetimes = sorted(iterate_restart_datetimes(log_folder, log_files, start_date, end_date))
    return restart_datetimes

def get_restart_datetimes_cluster(log_folder, log_files, start_date=None, end_date=None):
    # Retrieve restart datetimes
    restart_datetimes = sorted(iterate_restart_datetimes_cluster(log_folder, log_files, start_date, end_date))
    return restart_datetimes

def filter_restart_datetimes(restart_datetimes, start_datetime, end_date):
    filtered_restart_datetimes = list()
    for restart_datetime in restart_datetimes:
        if start_datetime and restart_datetime < start_datetime: continue
        if end_date and restart_datetime.date() > end_date: continue
        
        filtered_restart_datetimes.append(restart_datetime)
        
    return filtered_restart_datetimes
    
def export_restart_datetimes(restart_datetimes, path="./restart_datetimes.json"):
    json.dump(restart_datetimes, str(Path(path)))
    
def format_restart_datetimes(restart_datetimes):
    s = "\n".join(map("{}".format, restart_datetimes))                
    return s
