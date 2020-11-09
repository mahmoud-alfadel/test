"""Console script for dependency_threat."""
import sys
import click
from .dependency_threat import analyze
import pandas as pd
import os
from jinja2 import Template
path = os.path.abspath(__file__).rsplit("/", 1)[0]

def generate_html(df):
    try:
        author, repository = df['repo_name'][0].split("/")
    except:
        pass
    data = []
    for index, row in df.iterrows():
        data.append(row.to_dict())
    with open(os.path.join(path,"helper", "data", "template.html"), 'r') as f:
        template = Template(f.read())
        return template.render(
            data=data,
            author=author, 
            repository=repository, 
            intervals=list(df['interval']), 
            low_threats=list(df['affected_packages_low_list_count']),
            medium_threats=list(df['affected_packages_medium_list_count']),
            high_threats=list(df['affected_packages_high_list_count']),
            )

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
        with open(output_file.replace(".csv", ".html"), 'w') as f:
            f.write(generate_html(df))
        click.secho(
            " \n\033[1mOutput is saved in:\033[0m {}".format(output_file), fg="green"
        )
    else:
        with open('dependency_threat_report.html', 'w') as f:
            f.write(generate_html(df))
            click.secho(
            " \n\033[1mGenerated Report is saved in:\033[0m {}".format("dependency_threat_report.html"), fg="green"
        )
    return 0


if __name__ == "__main__":
    sys.exit(console())  # pragma: no cover
