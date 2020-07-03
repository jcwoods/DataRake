# DataRake
A regex-based forensics tool used to extract domain names, email addresses, network addresses, and keywords from directories full of text files.

To run:

    python3 datarake.py <path>

Pipe-delimited output includes filename, line number, match type, and match value.  This data is easily imported into your favorite spreadsheet.

TODO:
* Package as a real python module ;)
* Add a configuration file and command line options.
* Support whitelist or blacklist of file extensions per-Rake.
* Support "git clone" of repositories rather than local files only.
* Include scanning for JDBC URL patterns
* (maybe) find a data sciency way to reduce false positives.  Generating labelled data is fairly easy...
* Add context-aware Rakes (eg, use a C-tuned regex when searching C files for passwords).

