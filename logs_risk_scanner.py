import json
import logging
import os
import pathlib
import subprocess
import sys

import click


@click.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    '--output',
    '-o',
    type=click.File("w"),
    default=sys.stdout,
    help='Output file name to store found risks. Defaults to stdout',
)
def scan_logs_dir(directory, output):
    """
    Scans a local directory containing log files for risks using BluBracket CLI.
    """

    _scan_logs_dir(directory, output)


def _scan_logs_dir(directory, out):

    for root, dirs, files in os.walk(directory):

        for filename in files:
            path = os.path.join(root, filename)
            scan_file(path, directory, out)


def scan_file(path, root_dir, out):
    """
    Scans a single file

    Args:
        path: path to a file to scan
        root_dir: top-level directory to scan
        out: file like object to output the results to

    Returns:

    """
    try:
        _scan_file(path, root_dir, out)
    except Exception:
        # for this recipe we just want to print the exception and continue scanning
        logging.exception(f'Error while scanning {path}')


_log_exts = ['.log', '.txt', '.stdout']
_archive_ext = ['.tar', '.tgz', '.gz', '.zip', '.7z', '.bz2', '.tbz2']


def _scan_file(path, root_dir, out):

    # determine should the file be scanned or not
    # we want to scan log files only,
    # so let decide that a file is a log file based on the file's extension
    # TODO: pass a list of extensions to scan as a command parameter
    all_ext = _log_exts + _archive_ext

    rel_path = os.path.relpath(path, root_dir)

    ext = pathlib.Path(path).suffix
    if ext not in all_ext:
        click.echo(f'skipping {rel_path}')
        return

    click.echo(f'scanning {rel_path}')

    # run CLI as a subprocess to scan a single file
    # note: as there is no `--output` parameter, the output will go to stdout
    cli_cmd = [
        "blubracket",
        # scan-file instructs CLI to scan a single file
        "scan-file",
        # file to scan
        # note: no need to use --filename parameter as `path` will be used
        "--input",
        path,
    ]

    with subprocess.Popen(cli_cmd, stdin=None, stdout=subprocess.PIPE) as cli_process:
        try:
            _get_and_process_risks(root_dir, ext, cli_process.stdout, out)
        except BrokenPipeError:
            # CLI might not support handling of particular archive files,
            # in that case CLI will exit without reading the input data
            # this will lead to BrokenPipeError in cli_process.stdout.readlines()
            # 'ignore' it as it is a real error
            click.echo(f'skipping {rel_path}')


def _get_and_process_risks(root_dir, ext, input_file, out):

    for risk_line in input_file.readlines():

        risk_line = risk_line.decode('utf-8')

        # for real log files, just dump the result to out
        if ext in _log_exts:
            out.write(risk_line)
            out.flush()
            continue

        # must be an archive file
        # there can be different files in the archive, so we want to filter out the collected risks
        # CLI outputs data in json lines format, so each line is a valid json object
        # load it
        risk = json.loads(risk_line)
        risk_local_path = risk.get('local_path', '')
        # risk_local_path supposed to have the full path that consists
        # of both path of the archive itself and path inside the archive, e.g. logs.zip:2022-05-12.log
        if not risk_local_path:
            continue

        # get the extension of archived file to determine should it be filtered out or not
        risk_file_ext = pathlib.Path(risk_local_path).suffix
        if risk_file_ext not in _log_exts:
            rel_path = os.path.relpath(risk_local_path, root_dir)
            click.echo(f'skipping {rel_path}')
            continue

        # seems a risk from an archived log file
        out.write(risk_line)
        out.flush()
        continue


if __name__ == '__main__':
    scan_logs_dir()
