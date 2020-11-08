"""Console script for dependency_threat."""
import sys
import click
from .dependency_threat import analyze
import pandas as pd


@click.command()
@click.argument("url")
@click.option(
    "-i",
    "--i",
    "--interval",
    "interval",
    type=int,
    default=5,
    show_default=True,
    help="set custom commit interval",
)
@click.option(
    "-o",
    "--o",
    "--output_file",
    "output_file",
    type=str,
    help="name & path of the output csv file. By Default it will save in the current folder.",
)
def console(url, interval, output_file):
    """ \n\033[1m✨ Dependency Threat ✨\033[0m - Analyze Github Repository to Find NPM Vulnerabilities."""

    df = analyze(url, interval)
    if output_file:
        df.to_csv(output_file, index=False)
        click.secho(
            " \n\033[1mOutput is saved in:\033[0m {}".format(output_file), fg="green"
        )
    return 0


if __name__ == "__main__":
    sys.exit(console())  # pragma: no cover
