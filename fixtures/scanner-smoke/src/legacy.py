import subprocess


def run_report(path):
    command = "cat " + path
    return subprocess.check_output(command, shell=True)
