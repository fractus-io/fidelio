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
from download_cve import download_cve
from unzip import unzipJson


@click.command()
@click.option('-d', '--download', nargs=2, help='Downloads CVE or CPE files and putes them in a folder')
def main(download):
    download_cve(download[0], download[1])
    # big_list = unzipJson()
    # # print(big_list[0])

