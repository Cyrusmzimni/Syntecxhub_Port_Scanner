import socket #go ahead and bring in this functionality that's already there.
import subprocess
import sys

from datetime import datetime #We want to the current time so we can see how long the scan took.

subprocess.call('clear', shell=True) #make it go away.

remoteServer    = input("Enter a remote host to scan: ")
remoteServerIP  = socket.gethostbyname(remoteServer)

#print a nice banner with information on which host we are about to scan
print("=" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("=" * 60)

#check the date and time the scan started
tl = datetime.now()

#Using the range function to specify ports (here it will scans all ports between 1 and 1024)
#Also well do error handling to catch any errors

try:
    for port in range(1,1024):  #scan all ports between 1 and 100
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) 
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print("Port {}: Open".format(port))
        sock.close()

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved. Exiting")
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()

#check the date and time the scan ended
t2 = datetime.now()

#calculate the difference in time to see how long it took to run the script
total = t2 - tl

print("Scan completed in: ", total)