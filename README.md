# Running DataRake
A regex-based forensics tool used to extract secrets (passwords, tokens, keys, etc) from directories full of text files.

DataRake can be installed for local use or run from an OCI (Docker) container.  Each method is documented below.

## Running Local

The packages are in the artifactoryprod PyPI repository at https://artifactoryprod.es.ad.adp.com/artifactory/api/pypi/innerspace-pypi/simple.  Add this repository to your ~/.pip/pip.conf file either as your index-url or as an extra-index-url:

    [global]
    index-url = ...(your primary index here)...
    extra-index-url =  https://artifactoryprod.es.ad.adp.com/artifactory/api/pypi/innerspace-pypi/simple

With pip configured to use the innerspace-pypi repository, installation should be as simple as:

    $ pip install datarake

### Command line args
To run from command line:

    usage: __main__.py [-h] [-n] [-e] [-d DOMAIN] [-j] [-dp] [-dt] [-dh] [-dk] [-du] [-df] [-dc] [-f {csv,json,insights}] [-o OUTPUT] [-s] [-dx] [-dv] [PATH [PATH ...]]
    
    positional arguments:
      PATH                  Path to be (recursively) searched.
    
    optional arguments:
      -h, --help            show this help message and exit
      -n, --hostname        scan for hostnames, optionally rooted in DOMAIN.
      -e, --email           scan for email addresses, optionally rooted in DOMAIN.
      -d DOMAIN, --domain DOMAIN
                            for hostname and emails, require that they are rooted in DOMAIN. If no DOMAIN is specified and either hostname or email matching is enabled, any pattern matching a host or
                            email will be reported
      -j, --jwt             scan for Javascript Web Tokens (JWT)
      -dp, --disable-passwords
                            disable scan for passwords
      -dt, --disable-tokens
                            disable scan for tokens
      -dh, --disable-headers
                            disable scan for common auth headers
      -dk, --disable-private-keys
                            disable scan for private key files.
      -du, --disable-urls   disable scan for credentials in URLs
      -df, --disable-dangerous-files
                            disable detection of dangerous files
      -dc, --disable-dangerous-commands
                            disable detection of dangerous commands
      -f {csv,json,insights}, --format {csv,json,insights}
                            Output format
      -o OUTPUT, --output OUTPUT
                            Output location (defaults to stdout)
      -s, --secure          Enable secure output mode (no secrets displayed)
      -dx, --disable-context
                            Disable output of context match
      -dv, --disable-value  Disable output of secret match

## Running with docker

To run from Docker image (with defaults), bind your directory to /scan:

    docker run -v $PWD:$PWD -w $PWD dtr.cdl.es.ad.adp.com/innerspace/datarake . 

The given path(s) will be traversed recursively. 

# Design Notes

Top level objects include DirectoryWalker, Rake, RakeSet, and RakeMatch.

## DirectoryWalker

Recursively traverses a directory.  It supports a list of directories which will be pruned (skipped).  Each file discovered within the directory will be returned as a "context" tuple, including path, file name, and file type.

The DirectoryWalker is implemented as an iterator.

## Rake
In general, a Rake is an abstract base class which finds "issues".  When an issue is found, it creates a RakeMatch.

Rake contains subclasses:
* RakePattern - a pattern-based detector.
* FileTypeContextRake - applies different patterns based on file type (extension).
* RakeEntropy - detects areas within files that rank as high entropy (randomness, as keys, passwords, etc).  Entropy measure is discussed further below.
* RakeFileMeta - identifies issues based on file metadata, such as names (eg, id_rsa, .npmrc).

### RakePattern
A regex-based detection engine. Not useful by itself, RakePattern is further subclassed by:

*  RakeHostname - detects hostnames.  If a domain is specified, host names must be rooted in the given domain.
*  RakeURL - Detects URLs.  By default, only URLs containing username and password are reported (but this may be disabled).
*  RakeEmail - detects email addresses.  If a domain is specified, host names must be rooted in the given domain.
*  RakePrivateKey - detect private key files (eg, "-----BEGIN RSA PRIVATE KEY-----").
*  RakeBearerAuth - detect Bearer authentication tokens (as might appear in an HTTP Authorization header)
*  RakeBasicAuth - detect Basic authentication tokens (as might appear in an HTTP Authorization header).  The decoded value must be base64-encoded and match "user:password" pattern.
*  RakeAWSHMACAuth - detect Bearer authentication tokens (as might appear in an HTTP Authorization header)
*  RakeJWT - detect Javascript web tokens (JWT)
*  RakeBase64 - detect base64-encoded text data (UTF-8 encoded)
*  RakeSSHPass - detect use of the 'sshpass' command.

### FileTypeContextRake

Much like RakePattern, but patterns are specified by file type (extension).  This makes the patterns context-aware to an extent and drives down false positives.

FileTypeeContextRake is not directly used, but is subclassed by:

* RakeToken - detects token, authtoken, and tok patterns where a literal value is assigned.
* RakePassword - detects password, pass, and passw patterns where a literal value is assigned.

### RakeEntropy

Detects areas of high entropy ("randomness") using the Shanon Entropy measure.

A parameter is required which specifies the length of strings considered as well as a minimum entropy score.  A recommended starting point is:

* 32 character substrings.  This covers a minimum of 128-bit hex encoded key.
* An entropy score of 4.875.  The maximum score for a 32 character string is 5, so this requires very random data (eg, perhaps one repeated character of the 32).

### RakeFileMeta

Given metainformation about a file (path, name, type, etc), perform some basic checks.

* RakeSSHIdentity - detect SSH identity (private key) files
* RakeNetrc - detect .netrc files
* RakePKIKeyFiles - detect file types commonly associated with PKI/X.509 certificates
* RakeKeystoreFiles - detect common Java keystore files
* RakeHtpasswdFiles - detect Apache .htpasswd files

## RakeSet

A RakeSet is a collection of Rakes.  File metadata and content are fed to the RakeSet, and each Rake is applied in turn.

## RakeMatch

When a Rake identifies an issue, it generates a RakeMatch.  The RakeMatch includes the path/file, location (if relevant), issue description, and matching text (if relevant).  These are formatted to generate output.

# TODO:

(done) * Package as a real python module ;)
* Add unit tests to detect regressions, measure improvements.
* Add a configuration file.  This would be more flexible than command line.
* Add common patterns from shhgit (GCP, AWS, Azure, Slack, etc).
* Include scanning for credentials embedded in JDBC URL patterns
* (maybe) find a data sciency way to reduce false positives.  Generating labelled data is fairly easy.