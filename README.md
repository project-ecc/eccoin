Eccoin integration/staging tree
=====================================

https://ecc.network

What is ECC?
----------------

ECC is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. ECC uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network.

License
-------
[![LICENSE](https://img.shields.io/github/license/project-ecc/eccoin.svg)](https://github.com/project-ecc/eccoin/blob/master/LICENSE)

All contributions and releases are made under the GNU General Public License v3. See [LICENSE](https://github.com/project-ecc/eccoin/blob/master/LICENSE).


Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/project-ecc/eccoin/tags) are created
regularly to indicate new official, stable release versions of Eccoin.

The contribution workflow is described in [contributing.md](contributing.md).


Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows and Linux and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
