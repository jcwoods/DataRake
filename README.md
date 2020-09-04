>
> Cloned from upstream https://github.com/jcwoods/DataRake on 2020-09-02.  This version contains:
> * Dockerfile, to make running it a bit easier.
>

# DataRake
A regex-based forensics tool used to extract secrets (passwords, tokens, keys, etc) from directories full of text files.

To run from command line:

    usage: datarake.py [-h] [-n] [-e] [-d DOMAIN] [-r [RANDOM]] [-b [BASE64]]
                       [-dp] [-dt] [-dh] [-dk]
                       PATH
    
    positional arguments:
      PATH                  Path to be (recursively) searched.
    
    optional arguments:
      -h, --help            show this help message and exit
      -n, --hostname        scan for hostnames, optionally rooted in DOMAIN.
      -e, --email           scan for email addresses, optionally rooted in DOMAIN.
      -d DOMAIN, --domain DOMAIN
                            for hostname and emails, require that they are rooted
                            in DOMAIN. If no DOMAIN is specified and either
                            hostname or email matching is enabled, any pattern
                            matching a host or email will be reported
      -r [RANDOM], --random [RANDOM]
                            scan for high entropy strings. RANDOM is a threshold
                            formatted <bytes>:<entropy>, where <bytes> is the
                            length of strings measured and <entropy> is the Shanon
                            entropy score. If you're unsure, start with RANDOM set
                            as '32:4.875' and tune from there.
      -b [BASE64], --base64 [BASE64]
                            scan for base64-encoded text with minimum encoded
                            length of BASE64.
      -dp, --disable-passwords
                            disable scan for passwords
      -dt, --disable-tokens
                            disable scan for tokens
      -dh, --disable-headers
                            disable scan for common auth headers
      -dk, --disable-private_keys
                            disable scan for private key files.

To run from Docker image (with defaults), bind your directory to /scan:

    docker run -v /local/volume:/scan datarake

The given path(s) will be traversed recursively.  Pipe-delimited output includes filename, line number, match type, and match value.  This data is easily imported into your favorite spreadsheet.

TODO:
* Package as a real python module ;)
* Unit testing
* Add a configuration file
* Support whitelist or blacklist of file extensions per-Rake.
* Support "git clone" of repositories rather than local files only.
* Add common patterns from shhgit (GCP, AWS, Azure, Slack, etc).
* Include scanning for JDBC URL patterns
* Detect JWT (base64 + structure)
* Allow filters to remove noisy false positives (URLs with "example.com", suppress base64 hits in .pem, .crt, id_*, etc)
* (maybe) find a data sciency way to reduce false positives.  Generating labelled data is fairly easy...

