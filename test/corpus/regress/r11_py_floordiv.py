import subprocess


def run(host):
    # 这一行的 // 是整除，不是注释；当成注释会吞掉后面的引号，把下一行 sink 一起抹掉
    pad = "x" * (len(host) // 2)
    subprocess.run("ping -c 1 " + host, shell=True)
