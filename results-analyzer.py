"""
This file contains the code that does the "pulling". It requests all of the files that the user
has submitted to Assemblyline for analysis via the "pusher".

There are 4 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import logging
import click
from re import match
from time import sleep

from assemblyline_client import get_client

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "puller.log"
REPORT_FILE = "report.csv"

# These are regular expressions used for parameter validation that the user supplies
IP_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
DOMAIN_REGEX = r"(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+" \
               r"(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?)"
URI_PATH = r"(?:[/?#]\S*)"
FULL_URI = f"^((?:(?:[A-Za-z]*:)?//)?(?:\\S+(?::\\S*)?@)?(?:{IP_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?){URI_PATH}?$"

# These are details related to the log file.
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    level=logging.DEBUG
)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
log = logging.getLogger(__name__)


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("-u", "--username", required=True, type=click.STRING, help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.STRING,
              help="Your Assemblyline account API key. NOTE that this API key requires read access.")
@click.option("--min_score", default=0, type=click.INT, help="The minimum score for files that we want to query from Assemblyline.")
@click.option("--incident_num", required=True, type=click.STRING, help="The incident number for each file to be associated with.")
def main(url: str, username: str, apikey: str, min_score: int, incident_num: int):
    """
    Example:
    python3 results-analyzer.py --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="<api-key-name>:<key>" --incident_num=123
    """
    # Phase 1: Parameter validation
    try:
        validate_parameters(url)
    except Exception as e:
        # If there are any exceptions raised at this point, bail!
        print(e)
        log.error(e)
        return

    # Phase 2: Create the Assemblyline Client
    al_client = get_client(url, apikey=(username, apikey))

    # Phase 3: Open important files and read their contents
    report_file = open(REPORT_FILE, "a")
    report_file.write("SHA256,Score,URL,Errors\n")
    # Phase 4: Get submission details for each ingest_id
    log.debug(f"Searching for the submission for incident number {incident_num}")
    submission_res = al_client.search.stream.submission(f"params.description:'Incident Number\: {incident_num}' AND max_score:>={min_score}")
    for submission in submission_res:

        # Phase 5: Wait until the submission has completed
        state = submission["state"]
        while state != "completed":
            msg = f"{submission['sid']} is still in the state:{state}. Sleeping for 2 seconds and trying again."
            print(msg)
            log.debug(msg)
            sleep(2)
            specific_submission_res = al_client.submission.full(submission["sid"])
            state = specific_submission_res["state"]

        # Deep dive into the submission to get the files
        full_sub = al_client.submission.full(submission["sid"])
        for file in full_sub["files"]:

            # Report accordingly.
            msg = f"{file['sha256']},{full_sub['max_score']},{url}/submission/report/{submission['sid']},{full_sub['errors']}\n"
            print(msg)
            log.debug(msg)
            report_file.write(msg)

    msg = "All done!"
    print(msg)
    log.debug(msg)


def validate_parameters(url: str):
    _validate_url(url)


def _validate_url(url: str) -> bool:
    if match(FULL_URI, url):
        return True
    else:
        raise Exception(f"Invalid URL {url}.")


if __name__ == "__main__":
    main()