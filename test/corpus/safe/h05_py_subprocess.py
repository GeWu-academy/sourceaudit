import subprocess
def run(host):
    subprocess.run(['ping', '-c', '1', host], check=False)
