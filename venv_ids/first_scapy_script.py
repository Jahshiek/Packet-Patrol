import sys
from scapy.all import *

# test = IP()/TCP()
# print(test.show())

capture =sniff(filter="tcp", count=5)
print(capture.summary())



# try:
#     import sys
#     from scapy.all import *

#     print("All packages are installed!")
# except ImportError as e:
#     print(f"Missing package: {e.name}")
