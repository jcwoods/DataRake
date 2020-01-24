# DataRake
A regex-based forensics tool used to extract domain names, email addresses, network addresses, and keywords from directories full of text files.

To run:

    python3 datarake.py <rootdomain> file1 [[file2]...]

For recursive operation, consider:

    find /path/to/data -type f -print0 | xargs -0 python3 datarake.py mydomain.com 

Pipe-delimited output includes filename, line number, match type, and match value.

TODO:
* Add a configuration file.
* Add native directory scanning (break reliance on external find command)
* Support whitelist or blacklist of file extensions.
* Support "git clone" of repositories rather than local files only.
* Include scanning for JDBC URLs
* Include "high entropy" values (nod to trufflehog).
