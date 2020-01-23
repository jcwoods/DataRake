# DataRake
a forensics tool used to extract domain names, email addresses, network addresses, and keywords from directories full of text files.

To run:

python3 datarake.py <rootdomain> file1 [[file2]...]

For recursive operation, consider:

find /path/to/data -type f -print0 | xargs -0 python3 datarake.py mydomain.com 

