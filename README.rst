========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - |
        |
    * - package
      - | |commits-since|
.. |docs| image:: https://readthedocs.org/projects/fidelio/badge/?style=flat
    :target: https://readthedocs.org/projects/fidelio
    :alt: Documentation Status

.. |commits-since| image:: https://img.shields.io/github/commits-since/filipStar/fidelio/v0.0.1.svg
    :alt: Commits since latest release
    :target: https://github.com/filipStar/fidelio/compare/v0.0.1...master



.. end-badges

An application for downloading and displaying Common Vulnerabilities and Exposures (CVE) from the National Vulnerabilities Database (NVD)

Installation
============

::

    pip install fidelio

You can also install the in-development version with::

    pip install https://github.com/filipStar/fidelio/archive/master.zip


Documentation
=============

(Not available yet)
https://fidelio.readthedocs.io/


Development
===========

To run the all tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
            
