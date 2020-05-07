# DataRake
A regex-based forensics tool used to extract domain names, email addresses, network addresses, and keywords from directories full of text files.

To run:

    python3 datarake.py <rootdomain> file1 [[file2]...]

For recursive operation, consider:

    find /path/to/data -type f -print0 | xargs -0 python3 datarake.py mydomain.com 

Pipe-delimited output includes filename, line number, match type, and match value.  This data is easily imported into your favorite spreadsheet.

TODO:
* Package as a real python module ;)
* Add a configuration file and command line options.
* Add native directory scanning (break reliance on external find command)
* Support whitelist or blacklist of file extensions.
* Support "git clone" of repositories rather than local files only.
* Include scanning for JDBC URL patterns
* Look for PGP headers on private keys (eg, -----BEGIN (EC|DSA|RSA) PRIVATE KEY-----)
* Change the hostname object to include an initializer which REQIRES a user/pass to be present for a hit.
* Find a data sciency way to reduce false positives.  Generating labelled data is fairly easy...
