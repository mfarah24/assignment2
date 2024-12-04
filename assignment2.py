#!/usr/bin/env python3

'''
OPS445 Assignment 2 - FALL 2024
Program: assignment2.py
The python code in this file is original work written by
Mohamed A. Farah. No code in this file is copied from any other source
except those provided by the course instructor, including any person,
textbook, or online resource. I have not shared this python script
with anyone or anything except for submission for grading. I understand
that the Academic Honesty Policy will be enforced and
violators will be reported and appropriate action will be taken.

Author: Mohamed A. Farah - 134682228
Description: Assignment 2 - Version A
This script will return memory usage information in a bar chart format.
'''

import argparse
import os
import sys

def parse_command_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the Memory Visualiser program.

    Returns:
        argparse.Namespace: Parsed command-line arguments as an object.
    """
    parser = argparse.ArgumentParser(
        description="Memory Visualiser -- See Memory Usage Report with bar charts",
        epilog="Copyright 2023"
    )
    parser.add_argument(
        "-H", "--human-readable",
        action='store_true',
        help="Prints sizes in human-readable format"
    )
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=20,
        help="Specify the length of the graph. Default is 20."
    )
    parser.add_argument(
        "program",
        type=str,
        nargs='?',
        help="If a program is specified, show memory use of all associated processes. Show only total use if not."
    )

    args = parser.parse_args()

    # Validate length
    if args.length <= 0:
        parser.error("The length (-l) must be a positive integer.")

    return args

def get_sys_mem() -> int:
    """
    Get total system memory in KiB from /proc/meminfo.

    Returns:
        int: Total memory in KiB.
    """
    with open("/proc/meminfo", "r") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                return int(line.split()[1])  # Memory in KiB

def get_avail_mem() -> int:
    """
    Get available system memory in KiB from /proc/meminfo.

    Returns:
        int: Available memory in KiB.
    """
    with open("/proc/meminfo", "r") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])  # Memory in KiB

def percent_to_graph(percentage: float, length: int = 20) -> str:
    """
    Convert a percentage into a bar graph representation.

    Args:
        percentage (float): A value between 0.0 and 1.0.
        length (int): Length of the bar graph.

    Returns:
        str: Bar graph as a string.
    """
    num_hashes = int(percentage * length)
    return "#" * num_hashes + " " * (length - num_hashes)

def human_readable_format(size_in_kib: int) -> str:
    """
    Convert a size in KiB to a human-readable format (MiB, GiB, etc.).

    Args:
        size_in_kib (int): Size in KiB.

    Returns:
        str: Human-readable string.
    """
    units = ['KiB', 'MiB', 'GiB', 'TiB']
    size = size_in_kib
    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

def display_total_memory(human_readable: bool, length: int):
    """
    Display total memory usage as a bar graph.

    Args:
        human_readable (bool): Whether to display in human-readable format.
        length (int): Length of the bar graph.
    """
    total_mem = get_sys_mem()
    avail_mem = get_avail_mem()
    used_mem = total_mem - avail_mem
    usage_percentage = used_mem / total_mem

    if human_readable:
        total_str = human_readable_format(total_mem)
        used_str = human_readable_format(used_mem)
    else:
        total_str = f"{total_mem} KiB"
        used_str = f"{used_mem} KiB"

    graph = percent_to_graph(usage_percentage, length)
    print(f"Memory         [{graph:<{length}} | {int(usage_percentage * 100)}%] {used_str}/{total_str}")

def pids_of_prog(program: str) -> list:
    """
    Get the PIDs of a program using the `pidof` command.

    Args:
        program (str): The name of the program.

    Returns:
        list: List of PIDs (as strings) associated with the program.
    """
    try:
        pids = os.popen(f"pidof {program}").read().strip()
        if not pids:
            return []
        return pids.split()  # Return list of strings
    except Exception as e:
        print(f"Error fetching PIDs for '{program}': {e}")
        return []

def rss_mem_of_pid(pid: str) -> int:
    """
    Calculate the Resident Set Size (RSS) memory of a process.

    Args:
        pid (str): Process ID.

    Returns:
        int: Total RSS memory used by the process in KiB.
    """
    rss_total = 0
    try:
        with open(f"/proc/{pid}/smaps", "r") as f:
            for line in f:
                if line.startswith("Rss:"):
                    rss_total += int(line.split()[1])
    except FileNotFoundError:
        pass  # Process no longer exists
    except Exception as e:
        print(f"Error reading smaps for PID {pid}: {e}")
    return rss_total

def display_program_memory(program: str, human_readable: bool, length: int):
    """
    Display memory usage for all processes of a specified program.

    Args:
        program (str): The name of the program.
        human_readable (bool): Whether to display in human-readable format.
        length (int): Length of the bar graph.
    """
    pids = pids_of_prog(program)

    if not pids:
        print(f"{program} not found.")
        return

    total_mem = get_sys_mem()
    program_total_rss = 0

    print(f"Memory usage for {program}:")
    for pid in pids:
        rss = rss_mem_of_pid(pid)
        program_total_rss += rss
        usage_percentage = rss / total_mem
        graph = percent_to_graph(usage_percentage, length)

        if human_readable:
            rss_str = human_readable_format(rss)
        else:
            rss_str = f"{rss} KiB"

        print(f"PID {pid:<10} [{graph:<{length}} | {int(usage_percentage * 100)}%] {rss_str}/{human_readable_format(total_mem) if human_readable else f'{total_mem} KiB'}")

    print(f"Total RSS for {program}: {human_readable_format(program_total_rss) if human_readable else f'{program_total_rss} KiB'}")

def main():
    """Main function to handle program logic."""
    args = parse_command_args()

    if not args.program:
        display_total_memory(args.human_readable, args.length)
    else:
        display_program_memory(args.program, args.human_readable, args.length)

if __name__ == "__main__":
    main()
