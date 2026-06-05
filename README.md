# Running DataRake

A regex-based forensics tool used to extract secrets (passwords, tokens, keys, etc) from directories full of text files.

DataRake can be installed for local use or run from an OCI (Docker) container.  Each method is documented below.

As many as two different outputs may be returned for each issue identified:  a context and/or a value.  The context is useful when the results are being reviewed by a human, and provides a small amount of information about the context in which the secret was found.  This may be useful when manually reviewing results.

The value is the specific data which is /believed/ to be the secret.  This is useful with automated processes which might remove/replace the sensitive data.

As an example, assume I have a simple properties file:

    $ cat src/project.properties
    username=jeffw
    password=Sup3rSekrit!

Running datarake finds the offensive value, reporting both a context and a value:

    $ datarake --format=json
    [
      {
        "description": "possible plaintext password",
        "line": 2,
        "path": "src/project.properties",
        "severity": "HIGH",
        "type": "password",
        "context": {
            "length": 21,
            "offset": 0,
            "value": "password=Sup3rSekrit!"
        },
        "value": {
            "length": 12,
            "offset": 9,
            "value": "Sup3rSekrit!"
        }
      }
    ]

Now assume that we want to mask the sensitive data using an automated process, such as ‘sed’.  If we use the context, it grabs too much data (we lose the “password=”):

    $ sed  -e 's/password=Sup3rSekrit!/********/g' src/project.properties
    username=jwoods
    ********

If we replace ONLY the value, we get the desired result:

    $ sed  -e 's/Sup3rSekrit!/********/g' src/project.properties
    username=jwoods
    password=********

At the same time, the context is output to help in the evaluation of results.  It should provide enough context about the match that it can be understood easily.

## Installing Local

    $ pip install .

This installs the `datarake` command and bundles the default configuration
(`datarake.yaml`) inside the package, so it is found automatically without
specifying `-c`.

### Configuration

What datarake scans for is driven entirely by a YAML configuration file.  A
default configuration ships with the package and is used automatically.  To
use your own, pass `-c/--config`:

    $ datarake -c /path/to/my-datarake.yaml /path/to/code

The configuration defines the set of *Rakes* (patterns and file-metadata
matchers) plus a *FilterRegistry* of reusable named filters and filter sets
used to suppress false positives.  See the bundled `datarake/datarake.yaml`
for a complete, commented example.

### Command line args

Once installed, to run from command line:

    usage: datarake [-h] [-f {csv,json,sarif}] [-o OUTPUT] [-s] [-dx] [-dv]
                    [-u] [-q] [-v] [-j JOBS] [-c CONFIG]
                    [PATH ...]

    positional arguments:
      PATH                  Path to be (recursively) searched.

    options:
      -h, --help            show this help message and exit
      -f {csv,json,sarif}, --format {csv,json,sarif}
                            Output format
      -o OUTPUT, --output OUTPUT
                            Output location (defaults to stdout)
      -s, --secure          Enable secure output mode (no secrets displayed,
                            secure context)
      -dx, --disable-context
                            Disable output of context match
      -dv, --disable-value  Disable output of secret matched
      -u, --summary         enable output of summary statistics
      -q, --quiet           Do not output scan results, summary information only.
      -v, --verbose         Enable verbose (diagnostic) output
      -j JOBS, --jobs JOBS  Number of worker threads used to scan files
                            (default: CPU count)
      -c CONFIG, --config CONFIG
                            Configuration file (defaults to the bundled
                            datarake.yaml)

Files are scanned concurrently by a pool of worker threads (`-j/--jobs`).
All output is serialized through the main thread, so results are emitted in
a deterministic order regardless of the number of workers.

## Installing Container

    $ docker build -t datarake:latest .
    $ docker run -it -v /path/to/code:/src datarake.latest

# Design Notes

Top level objects include DirectoryWalker, Rake, RakeSet, and RakeMatch.

## DirectoryWalker

Recursively traverses a directory.  It supports a list of directories which will be pruned (skipped).  Each file discovered beneath the directory will be returned as a "context" tuple, including path, file name, and file type (extension).

The DirectoryWalker object supports the iterator pattern.

## Rake

Conceptually, a Rake is an abstract base class which finds "issues".  When an issue is found, it creates a RakeMatch.

A rake is implemented as one of a few subclasses:

* RakePattern - a pattern-based detector (regular expressions).
* FileTypeContextRake - applies a different RakePattern based on file type for current context.
* RakeEntropy - detects areas within files that rank as high entropy (randomness, as keys, passwords, etc).  Entropy measure is discussed further below.
* RakeFileMeta - identifies issues based on file metadata, such as names (eg, id_rsa, .npmrc).

Each Rake may optionally implement filters.  Once a match is detected, the logic in the filter (if any) is applied to the match and match context.  This might be useful for suppressing hits on common passwords, for instance.

### RakePattern

A regex-based detection engine. Not useful by itself, RakePattern is further subclassed by:

* RakeHostname - detects hostnames.  If a domain is specified, host names must be rooted in the given domain.
* RakeURL - Detects URLs.  By default, only URLs containing username and password are reported (but this may be disabled).
* RakeEmail - detects email addresses.  If a domain is specified, host names must be rooted in the given domain.
* RakePrivateKey - detect private key files (eg, "-----BEGIN RSA PRIVATE KEY-----").
* RakeBearerAuth - detect Bearer authentication tokens (as might appear in an HTTP Authorization header)
* RakeBasicAuth - detect Basic authentication tokens (as might appear in an HTTP Authorization header).  The decoded value must be base64-encoded and match "user:password" pattern.
* RakeAWSHMACAuth - detect Bearer authentication tokens (as might appear in an HTTP Authorization header)
* RakeJWT - detect Javascript web tokens (JWT)
* RakeBase64 - detect base64-encoded text data (UTF-8 encoded)
* RakeSSHPass - detect use of the 'sshpass' command.

### FileTypeContextRake

Much like RakePattern, but patterns are specified by file type (extension).  This makes the patterns context-aware (to an extent) and drives down false positives.

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

* Add unit tests to detect regressions, measure improvements.
* Add a configuration file.  This would be more flexible than command line.
* Add common patterns from shhgit (GCP, AWS, Azure, Slack, etc).
* Include scanning for credentials embedded in JDBC URL patterns
* (maybe) find a data sciency way to reduce false positives.  Generating labelled data is fairly easy.
