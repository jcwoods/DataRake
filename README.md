>
>Cloned from upstream https://github.com/jcwoods/DataRake on 2020-09-02.  This version contains:
>* Dockerfile, to make running it a bit easier.
>

# DataRake
A regex-based forensics tool used to extract secrets (passwords, tokens, keys, etc) from directories full of text files.

To run from command line:

    python3 datarake.py <path> [<path>, ...]

To run from Docker image, bind your directory to /scan:

    docker run -v /local/volume:/scan datarake

The given path(s) will be traversed recursively.  Pipe-delimited output includes filename, line number, match type, and match value.  This data is easily imported into your favorite spreadsheet.

TODO:
* Package as a real python module ;)
* Unit testing
* Add a configuration file and command line options.
* Support whitelist or blacklist of file extensions per-Rake.
* Support "git clone" of repositories rather than local files only.
* Add common patterns from shhgit (GCP, AWS, Azure, Slack, etc).
* Include scanning for JDBC URL patterns
* Detect JWT (base64 + structure)
* Allow filters to remove noisy false positives (URLs with "example.com", suppress base64 hits in .pem, .crt, id_*, etc)
* (maybe) find a data sciency way to reduce false positives.  Generating labelled data is fairly easy...
