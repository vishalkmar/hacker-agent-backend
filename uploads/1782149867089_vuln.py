import os
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
password = "supersecret123"
def run(cmd):
    os.system("ping " + cmd)   # command injection
