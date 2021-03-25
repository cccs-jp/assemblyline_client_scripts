"""
This file contains the code that does the "pushing". It submits all of the files that the  user
wants to have submitted to Assemblyline for analysis.

There are 10 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import click
import logging
import os
from hashlib import sha256
from queue import Queue
from re import match
from subprocess import check_output
from time import sleep
from typing import List

from assemblyline_client import get_client

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "pusher.log"
HASH_FILE = "hashes.txt"

# These are the max and min size of files able to be submitted to Assemblyline, in bytes
MAX_FILE_SIZE = 100000000
MIN_FILE_SIZE = 1

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


def get_id_from_data(data: bytes) -> str:
    """
    This method generates a sha256 hash for the data supplied aka the file contents of a file
    @param data: The file contents in bytes
    @return _hash: The sha256 hash of the file
    """
    sha256_hash = sha256(str(data).encode()).hexdigest()
    return sha256_hash


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("-u", "--username", required=True, type=click.STRING,  help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.STRING,
              help="Your Assemblyline account API key. NOTE that this API key requires write access.")
@click.option("--ttl", type=click.INT, default=1,
              help="The amount of time that you want your Assemblyline submissions to live on the Assemblyline system (in days).")
@click.option("--classification", required=True, type=click.STRING,
              help="The classification level for each file submitted to Assemblyline.")
@click.option("--service_selection", required=True, type=click.STRING,
              help="A comma-separated list (no spaces!) of service names to send files to.")
@click.option("-t", "--is_test", is_flag=True, help="A flag that indicates that you're running a test.")
@click.option("-p", "--path", required=True, type=click.Path(exists=True, readable=True),
              help="The directory path containing files that you want to submit to Assemblyline.")
@click.option("--fresh", is_flag=True, help="We do not care about previous runs and resuming those.")
@click.option("--wait", is_flag=True, help="Wait for the analysis of ingested files to complete.")
@click.option("--incident_num", required=True, type=click.INT,
              help="The incident number for each file to be associated with.")
def main(url: str, username: str, apikey: str, ttl: int, classification: str, service_selection: str, is_test: bool, path: str, fresh: bool, wait: bool, incident_num: int):
    # Phase 1: Parameter validation
    try:
        service_selection = validate_parameters(url, username, apikey, ttl, service_selection)
    except Exception as e:
        # If there are any exceptions raised at this point, bail!
        print(e)
        log.error(e)
        return

    # Phase 2: Setting the parameters
    settings = {
        "ttl": ttl,
        "description": f"Incident Number: {incident_num}",
        "ignore_cache": "true",
        "classification": classification,
        "services": {
            "selected": service_selection
        }
    }

    # Phase 3: Test mode
    if is_test:
        msg = f"The Assemblyline ingest settings you would use are: {settings}"
        print(msg)
        log.debug(msg)
        return

    # Phase 4: Initialize key variables
    hash_table = []
    if wait:
        notification_queue = Queue()
    number_of_files_ingested = 0
    if fresh and os.path.exists(HASH_FILE):
        os.remove(HASH_FILE)

    # Phase 5: Script Resumption Logic
    # If the script somehow crashed or stopped prematurely, then the text file containing
    # the hashes which have been ingested to Assemblyline will still exist on the host.
    # Therefore, we will check if that file exists, and if so, then we will grab the last
    # hash that has been ingested to Assemblyline and use that as our starting point for
    # the current run.
    resume_ingestion_sha = None
    skip = False
    if os.path.exists(HASH_FILE):
        # This grabs the last hash in the file.
        resume_ingestion_sha = check_output(["tail", "-1", HASH_FILE]).decode().strip("\n")
        # This adds the most recent hash that has been ingested to the hash table, so that
        # we do not re-ingest it during this run.
        hash_table.append(resume_ingestion_sha)
        skip = True

    # Create file handlers for the two information files we need.
    hash_file = open(HASH_FILE, "a+")

    # Phase 6: Create the Assemblyline Client
    al_client = get_client(url, apikey=(username, apikey))

    # Phase 7: Recursively go through every file in the provided folder and its subfolders.
    for root, dir_names, file_names in os.walk(path):
        for file_name in file_names:
            # Wrap everything in a try-catch so we become invincible
            try:
                file_path = os.path.join(root, file_name)
                file_size = os.path.getsize(file_path)

                if file_size > MAX_FILE_SIZE:
                    msg = f"{file_path} is too big. Size: {file_size} > {MAX_FILE_SIZE}."
                    print(msg)
                    log.debug(msg)
                    continue
                elif file_size < MIN_FILE_SIZE:
                    msg = f"{file_path} is too small. Size: {file_size} < {MIN_FILE_SIZE}."
                    print(msg)
                    log.debug(msg)
                    continue

                # Phase 8: Ingestion Logic

                # Create a sha256 hash using the file contents.
                sha = get_id_from_data(open(file_path, "rb").read())

                # We only care about files that occur after the last sha in the hash file
                if resume_ingestion_sha and resume_ingestion_sha == sha:
                    skip = False

                # If we have yet to come up to the file who matches the last submitted sha, continue looking!
                if skip:
                    continue

                # If file is in hash table, don't ingest it
                if sha in hash_table:
                    continue
                else:
                    hash_table.append(sha)

                # Phase 9: Ingestion and logging everything

                # Pre-ingestion logging
                pre_ingestion_message = f"{file_path} ({sha}) is about to be ingested."
                print(pre_ingestion_message)
                log.debug(pre_ingestion_message)

                # Actual ingestion
                if wait:
                    resp = al_client.ingest(path=file_path, fname=file_name, nq="notification_queue", params=settings)
                else:
                    resp = al_client.ingest(path=file_path, fname=file_name, params=settings)

                # Documenting the hash and the ingest_id into the text files
                number_of_files_ingested += 1
                hash_file.write(f"{sha}\n")
                ingest_id = resp['ingest_id']

                # Post ingestion logging
                post_ingestion_message = f"{file_path} ({sha}) has been ingested with ingest_id {ingest_id}."
                print(post_ingestion_message)
                log.debug(post_ingestion_message)
            except Exception as e:
                print(e)
                log.error(e)

    # Phase 10: The waiting game
    if wait:
        messages = al_client.ingest.get_message_list(nq="notification_queue")
        while len(messages) < number_of_files_ingested:
            messages = al_client.ingest.get_message_list(nq="notification_queue")
            sleep(2)

    msg = "All done!"
    print(msg)
    log.debug(msg)


def validate_parameters(url: str, username: str, apikey: str, ttl: int, service_selection: str) -> List[str]:
    _validate_url(url)
    # _validate_username(username)
    # _validate_apikey(apikey)
    # _validate_ttl(ttl)
    return _validate_service_selection(service_selection)


def _validate_url(url: str) -> bool:
    if match(FULL_URI, url):
        return True
    else:
        raise Exception(f"Invalid URL {url}.")


# def _validate_username(username: str) -> bool:
#     if somehow_validate():
#         return True
#     else:
#         raise Exception(f"Invalid username {username}")
#
#
# def _validate_apikey(apikey: str) -> bool:
#     if somehow_validate():
#         return True
#     else:
#         raise Exception(f"Invalid apikey {apikey}")


# def _validate_ttl(ttl: int) -> bool:
#     if somehow_validate():
#         return True
#     else:
#         raise Exception(f"Invalid ttl {ttl}")


def _validate_service_selection(service_selection: str) -> List[str]:
    services_selected = service_selection.split(",")
    for service_selected in services_selected:
        if not service_selected:
            raise Exception(f"Invalid service selected {service_selected} of {services_selected}")
    return services_selected


if __name__ == "__main__":
    main()
