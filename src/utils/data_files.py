import datetime
import sys
import json
from pathlib import Path

def iterate_log_dates(log_folder, start_date=None, end_date=None, date_format="%Y-%m-%d"):
    # Iterate children
    for child in log_folder.iterdir():
        # Directories only
        if not child.is_dir(): continue
        # Valid dates only
        try:
            date = datetime.datetime.strptime(child.name, date_format).replace(tzinfo=datetime.timezone.utc).date()
        except ValueError:
            continue
        # Valid period only
        if start_date and date < start_date: continue
        if end_date and date > end_date: continue
        
        yield date, child
        
def parse_filename(file_name, time_format="%H:%M:%S"):
    name_parts = file_name.split('.')
    
    orig_name = name_parts[0]
    parse_time = lambda period, start: datetime.datetime.strptime(period.split("-")[0 if start else 1], time_format).replace(tzinfo=datetime.timezone.utc).time()
    from_time = parse_time(name_parts[1], True)
    to_time = parse_time(name_parts[1], False)
    assert ".".join(name_parts[2:]) == "log.gz"
    
    return orig_name, from_time, to_time
        
def iterate_log_files(log_dates):
    for (log_date, date_dir) in log_dates:
        for log_file in date_dir.glob("*.*-*.log.gz"):
            try:
                orig_name, from_datetime, to_datetime = parse_filename(log_file.name)
            except:
                print("Skipping log file name {}".format(date_dir / log_file.name), file=sys.stderr)
                continue
            
            yield log_date, date_dir, orig_name, from_datetime, to_datetime, log_file
            
def get_logfile_names(log_folder, start_date=None, end_date=None):
    # Retrieve log dates
    log_dates = sorted(iterate_log_dates(log_folder, start_date, end_date), key=lambda x: x[0])
    
    # Retrieve log file names
    date_logs = sorted(iterate_log_files(log_dates), key=lambda x: x[3])
    log_files = {(log_date, date_dir.name) : dict() for (log_date, date_dir) in log_dates}
    
    # Structure log file names
    for (log_date, date_dir, orig_name, from_datetime, to_datetime, log_file) in date_logs:
        date_dict = log_files[(log_date, date_dir.name)]
        # Append times for log
        if orig_name not in date_dict: date_dict[orig_name] = list()
        log_files_entry = [from_datetime, to_datetime, log_file.name]
        date_dict[orig_name].append(log_files_entry)
    
    return log_files

def filter_logfile_names(log_files, start_datetime, end_date):
    filtered_log_files = dict()
    for (log_date, dir_name), value in log_files.items():
        
        # Filter date
        if start_datetime and log_date < start_datetime.date(): continue
        if end_date and log_date > end_date: continue
        
        # First date
        if (start_datetime and log_date == start_datetime.date()):
            # Partial date
            filtered_log_files[(log_date, dir_name)] = dict()
            for orig_name in log_files[(log_date, dir_name)]:
                if orig_name not in filtered_log_files[(log_date, dir_name)]:
                    filtered_log_files[(log_date, dir_name)][orig_name] = list()
                    for (from_datetime, to_datetime, file_name) in log_files[(log_date, dir_name)][orig_name]:
                        from_dt = datetime.datetime.combine(log_date, from_datetime).replace(tzinfo=datetime.timezone.utc)
                        if from_dt < start_datetime: continue
                        log_file_entry = [from_datetime, to_datetime, file_name]
                        filtered_log_files[(log_date, dir_name)][orig_name].append(log_file_entry)
        else:
            # Full date
            filtered_log_files[(log_date, dir_name)] = value
        
    return filtered_log_files

def export_logfile_names(log_files, path="./logfile_names.json"):
    json.dump(log_files, str(Path(path)))
    
def format_logfile_names(log_files):
    s = ""
    for (log_date, dir_name) in sorted(log_files, key=lambda x:x[0]):
        s += "Date {}: {} ".format(log_date, dir_name) + "\n"
        for orig_name in sorted(log_files[(log_date, dir_name)]):
            s += "\tFile: {}".format(orig_name) + "\n"
            for (from_datetime, to_datetime, file_name) in log_files[(log_date, dir_name)][orig_name]:
                s += "\t\tPeriod {} - {}: {}".format(from_datetime, to_datetime, file_name) + "\n"
                
    return s