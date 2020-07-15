========
Overview
========

An application for downloading and displaying Common Vulnerabilities and Exposures (CVE) from the National Vulnerabilities Database (NVD)

Installation
============

::

    pip install -i https://test.pypi.org/simple/ fidelio

If you install fidelio from project folder then run
::

    pip install -e .

Fidelio is not yet available on pypi, but on TestPyPi.

To check if the package has been successfully installed run:
::

    fidelio --version

You can also install the in-development version with::

    pip install https://github.com/filipStar/fidelio/archive/master.zip


Getting Started
===============

The purpose of fidelio is to make CVE easier to visualize, but what are CVEs in the first place?

CVE - is list of entries each containing an identification number, a description, 
and at least one public reference for publicly known cybersecurity vulnerabilities.

NVD - A vulnerability database built upon and fully synchronized with the CVE List 
so that any updates to CVE appear immediately in NVD.

Fidelio works by letting anybody download and display CVEs from the NVD with just a couple of commands.

Currently fidelio has 3 main features:

- A downloader which downloads CVE json files and CPE xml files
- A csv converter which converts the json and xml files to a .csv format (This is temporary and will be replaced with database interaction in the near future)
- A visualizer built with streamlit that displays information about CVEs and CPEs


Downloader
----------

The CVEs are seperated into yearly json files which contain all the vulnerabilities in that year."
To download a CVE file from a certain year use the command: 

*This will create a folder in your current working directory for storing these files*
::

    fidelio -d cve [YEAR]

Note that the earliest year available in the NVD is 2002.

You can also download all of the CVEs at once with this command:
::

    fidelio -d cve all

There is also an option available for downloading CPE files, 
but they are not implemented in the Fidelio Visualizer:
::

    fidelio -d cpe all

CPEs are all stored in one file so they cannot be downloaded based on year.

If you ever want to update your data use:
::
    fidelio -d cve update

Csv Converter
-------------

This feature is used for converting  downloaded CVE and CPE files to .csv files.
This is necessary because the Fidelio Visualizer currently uses these .csv files for displaying visualizations.
There is also a sample .csv file that comes with the package which the Fidelio Visualizer uses by default, but some of
the visualizations will not work correctly unless you have a converted .csv file.

*WARNING: The CVE and CPE files contain a lot of data. When converting to .csv the converted files might contain up to 1GB of data.
Depending on the amount of CVE files you have downloaded.* 

The command for converting CVEs to .csv is:
::

    fidelio -c cve

The command for converting CPEs to .csv is:
::

    fidelio -c cpe


Fidelio Visualizer
------------------

This feature will run a Streamlit app in your browser. By default it will display the data contained in the cve_sample file.
If a .csv is created with the Csv Converter it will automatically switch to the converted file.

To run the Fidelio Visualizer use the command:
::

    fidelio -r visualizer


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
            
