"""
Module that contains the command line app.

Why does this file exist, and why not put this in __main__?

  You might be tempted to import things from __main__ later, but that will cause
  problems: the code will get executed twice:

  - When you run `python -mfidelio` python will execute
    ``__main__.py`` as a script. That means there won't be any
    ``fidelio.__main__`` in ``sys.modules``.
  - When you import __main__ it will get executed again (as a module) because
    there's no ``fidelio.__main__`` in ``sys.modules``.

  Also see (1) from http://click.pocoo.org/5/setuptools/#setuptools-integration
"""
import click
from download_files import download_files
from unzip import *
import os
from pathlib import Path
import sys
from streamlit import cli as stcli


def run_streamlit():
    dirname = Path(os.path.dirname(__file__)).parent
    filename = os.path.join(dirname, 'app.py')
    sys.argv = ["streamlit", "run", filename]
    sys.exit(stcli.main())


@click.command()
@click.option('-d', '--download', nargs=2, help='Downloads CVE or CPE files and putes them in a folder')
@click.option('-r', '--run', type=str, help='Runs the visualizer')
@click.option('-c', '--csv', type=str, help='Makes a csv file for CVE or CPE')
@click.version_option()
def main(download, run, csv):
    if download:
        download_files(download[0], download[1])
    if run:
        if run == 'visualizer':
            run_streamlit()
        else:
            click.echo('Invalid option. Try visualizer.')
    if csv:
        if csv == 'cve':
            make_cve_csv()
            print('Added cve.csv')
        elif csv == 'cpe':
            make_cpe_csv()
            print('Added cpe.csv')
