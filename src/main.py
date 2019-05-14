#!/usr/bin/python3

import argparse
from pathlib import Path
import sys
import datetime        
from utils.data_files import get_logfile_names, filter_logfile_names
from utils.restarts import get_restart_datetimes, filter_restart_datetimes,\
    get_restart_datetimes_cluster
from utils.data_content import iterate_logs
from handlers.connections import Connections
from handlers.osquery_hosts import OsqueryHosts
from handlers.software import Software
from handlers.host_connections import HostConnections
    
def prepare_logfiles(log_folder, start_date, end_date, cluster_mode):
    # Browse all log files by name
    # Key: (log_date, date_dir.name)
    # Value: 
    #    Key: orig_name
    #    Value: from_datetime, to_datetime, log_file.name
    total_log_files = get_logfile_names(log_folder)
    if len(total_log_files) == 0:
        print("No logs found at all", file=sys.stderr)
        sys.exit(1)
    print("Found {} total days of log files".format(len(total_log_files)))
    
    # Detect restarts
    # List of datetime
    if cluster_mode:
        total_restart_datetimes = get_restart_datetimes_cluster(log_folder, total_log_files, end_date=end_date)
    else:
        total_restart_datetimes = get_restart_datetimes(log_folder, total_log_files, end_date=end_date)
    if len(total_restart_datetimes) == 0:
        print("No starts found at all", file=sys.stderr)
        sys.exit(1)
    
    # Filter restart datetimes
    restart_datetime = None 
    # Find closest restart to start date 
    if start_date:
        candidate_datetimes = [dt for dt in total_restart_datetimes if dt.date() < start_date]
        # Search in the past
        if candidate_datetimes:
            restart_datetime = max(candidate_datetimes)
        # Search in the future
        else:
            candidate_datetimes = [dt for dt in total_restart_datetimes if dt.date() >= start_date]
            if candidate_datetimes:
                restart_datetime = min(candidate_datetimes)
    # First restart
    else:
        restart_datetime = min(total_restart_datetimes)
    assert restart_datetime
    print("Starting analysis from {} for the period {} to {}".format(restart_datetime, start_date, end_date))
    
    # Filter log files
    log_files = filter_logfile_names(total_log_files, restart_datetime, end_date)
    if len(log_files) == 0:
        print("No logs found for the given date period", file=sys.stderr)
        sys.exit(1)
    print("Found {} days of log files in the given date period".format(sum(1 for d in log_files if not start_date or d[0] >= start_date)))
        
    # Filter restart datetimes
    restart_datetimes = filter_restart_datetimes(total_restart_datetimes, restart_datetime, end_date)
    assert len(restart_datetimes) >= 1
    restart_datetimes = restart_datetimes[1:]
    print("Detected {} restarts in the given date period".format(len(restart_datetimes)))
    print()
    
    return restart_datetime, restart_datetimes, log_files

def main(log_folder, start_date, end_date, cluster_mode):
    
    # Scan Log Files
    restart_datetime, restart_datetimes, log_files = prepare_logfiles(log_folder, start_date, end_date, cluster_mode)
    
    # Initialize Handlers
    handlers = dict()
    handlers["Osquery Hosts"] = OsqueryHosts(start_date, end_date)
    handlers["Connections"] = Connections(start_date, end_date)
    handlers["Software"] = Software(start_date, end_date)
    handlers["Host Connections"] = HostConnections(start_date, end_date)
    handlers_sequence = [
        ("osquery", "Osquery Hosts"), 
        ("conn", "Connections"),
        ("software", "Software"),
        ("osq-process_connections", "Host Connections"),
    ]

    host_events = 0
    
    # Iterate Handlers
    for (o_name, h_name) in handlers_sequence:
        
        # Get handler
        handler = handlers[h_name]
        
        # Signals
        started = False
        next_restart_idx = 0
        next_restart = restart_datetimes[0] if restart_datetimes else None
        
        # Find logs
        for (dir_name, file_name, 
             orig_name, from_dt, to_dt, 
             file_lines) in iterate_logs(log_folder, log_files, orig_name=o_name):
            
            # Log file name
            log_name = str(Path(dir_name) / file_name)
            
            # Signal start
            if not started and (not start_date or from_dt.date() >= start_date):
                handler.signal_start(restart_datetime.timestamp())
                started = True
            
            # Signal restart
            if next_restart and from_dt >= next_restart:
                handler.signal_restart(next_restart)
                next_restart_idx += 1
                next_restart = restart_datetimes[next_restart_idx] if next_restart_idx < len(restart_datetimes) else None
            
            # Process log
            handler.process_log(orig_name, log_name, from_dt, to_dt, file_lines)
            
        # Final analysis
        handler.process_end(handlers)
        
        # Final results 
        print("=== " + h_name + "===")
        print(handler.format_results())
        print()

if __name__ == '__main__':
    
    # Create Parser
    parser = argparse.ArgumentParser(description='Statistics about the zeek-osquery log files')
    
    # Define arguments
    parser.add_argument('cluster_mode', type=bool, help='Whether cluster mode is enabled or not')
    # - Log Folder
    parser.add_argument('--log_dir', type=str, default='/usr/local/bro', help='The log directory of Zeek')
    # - Start Date
    parser.add_argument('--start_date', type=str, help='The earliest day of log files (YYYY-MM-DD)')
    # - End Date
    parser.add_argument('--end_date', type=str, help='The latest day of log files (YYYY-MM-DD)')
    
    # Parse and assess arguments
    args = parser.parse_args()
    
    # - Log Directory
    log_folder = Path(args.log_dir)
    if (not log_folder.is_dir()):
        print("No valid log directory '{}'".format(log_folder), file=sys.stderr)
        sys.exit(1)
        
    # - Start Date
    if (args.start_date):
        try:
            dt = datetime.datetime.strptime(args.start_date, "%Y-%m-%d")
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            start_date = dt.date()
        except ValueError:
            print("Unable to parse start date '{}'".format(args.start_date), file=sys.stderr)
            sys.exit(1)
    else:
        start_date = None
        
    # - End Date
    if (args.end_date):
        try:
            dt = datetime.datetime.strptime(args.end_date, "%Y-%m-%d")
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            end_date = dt.date()
        except ValueError:
            print("Unable to parse end date '{}'".format(args.end_date), file=sys.stderr)
            sys.exit(1)
    else:
        end_date = None
    
    # - Dates
    if (start_date and end_date and end_date < start_date):
        print("End date must be after start date", file=sys.stderr)
        sys.exit(1)
    
    # Start Analysis
    main(log_folder, start_date, end_date, args.cluster_mode)
    
