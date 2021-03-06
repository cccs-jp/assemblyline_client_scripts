# General Description
This repository contains two Python scripts used for triaging compromised systems with Assemblyline.
1. The "Pusher" (`file-submitter.py`): pushes files from the compromised system to an Assemblyline
instance for analysis.
2. The "Puller" (`results-analyzer.py`): pulls the submissions from the
Assemblyline instance and reports on if the submissions are safe/unsafe.
   

# How the heck do I use this thing?
## General Process
The "Pusher" needs to run from the compromised machine, which needs network access to the Assemblyline instance
which it will be sending files to.

The "Puller" needs to run from a machine that has network access to the Assemblyline instance
which you sent files to via the "Pusher". It is considered good practice to run the "Puller" from a machine that 
isn't compromised.

## Prequisites
For the machine(s) running the "Pusher" and the "Puller":
- You will need at least Python 3
- You will need the `click` PIP module and its dependencies installed
- You will need the `assemblyline_client` PIP module and its dependencies installed. 
  [HOW-TO](https://cybercentrecanada.github.io/assemblyline4_docs/docs/user_manual/assemblyline_client.html)
- For the offline installation of these packages and libraries, see the Offline Installation section

In general:
- You will need the URL of an Assemblyline instance that you have an account on. 
  - Want to create your own Assemblyline instance? [HOW-TO](https://cybercentrecanada.github.io/assemblyline4_docs/docs/installation.html)
- You will need two API keys generated by Assemblyline, ideally one with read access and another with write access. 
  The Write-only key will be used for the "Pusher", and the Read-only key will be used for the "Puller".
  - It is considered best practice to not use an API key that has both Read-Write access on the compromised system, so 
  we *highly* recommend using two keys.
    
### Offline Installation
You will need to run the following code from a machine that has Internet access and then transfer it to the machine
that does not have Internet access.
#### Linux:
```
mkdir offline_packages
cd offline_packages
sudo su
apt-get install --download-only python3 python3-pip libffi-dev libssl-dev --reinstall -y
mv /var/cache/apt/archives/*.deb .
python3 -m pip download pip pycryptodome requests requests[security] python-baseconv python-socketio[client] socketio-client==0.5.7.4 click
python3 -m pip download assemblyline_client
cd ..
exit
tar -czvf offline_packages.tar.gz offline_packages/
Copy this file over using SCP, FTP or some other method
```

On the machine that is offline, do the following:
```
tar -xzvf offline_packages.tar.gz
cd offline_packages
sudo apt-get install ./*.deb -y
for x in `ls *.whl`;  do python3 -m pip install $x; done
```

#### Windows
WIP

## Run the thing!
### Pusher
On the compromised machine...

To get a sense of the options available to you:
```
python3 file-submitter.py --help
Usage: file-submitter.py [OPTIONS] COMMAND [ARGS]...

  Example: python3 file-submitter.py --url="https://<domain-of-Assemblyline-
  instance>" --username="<user-name>" --apikey="<api-key-name>:<key>"
  --classification="<classification>" --service_selection="<service-
  name>,<service-name>" --path "/path/to/compromised/directory"
  --incident_num=123

Options:
  --url TEXT                The target URL that hosts Assemblyline.
                            [required]

  -u, --username TEXT       Your Assemblyline account username.  [required]
  --apikey TEXT             Your Assemblyline account API key. NOTE that this
                            API key requires write access.  [required]

  --ttl INTEGER             The amount of time that you want your Assemblyline
                            submissions to live on the Assemblyline system (in
                            days).

  --classification TEXT     The classification level for each file submitted
                            to Assemblyline.  [required]

  --service_selection TEXT  A comma-separated list (no spaces!) of service
                            names to send files to.  [required]

  -t, --is_test             A flag that indicates that you're running a test.
  -p, --path PATH           The directory path containing files that you want
                            to submit to Assemblyline.  [required]

  -f, --fresh               We do not care about previous runs and resuming
                            those.

  --incident_num TEXT       The incident number for each file to be associated
                            with.  [required]

  --retries INTEGER         The number of times you want to retry submitting a
                            file after it has failed.

  --help                    Show this message and exit.
```

Example Usage:
```
python3 file-submitter.py --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="<api-key-name>:<key>" --ttl=<number-of-days-to-live> --classification="<classification>" --service_selection="<service-name>,<service-name>" -p "/path/to/compromised/directory" --incident_num=123
```

After a successful run you should get some logs, followed by "All done!"

You can check that these files were ingested successfully by browsing to the Submissions page of the
Assemblyline instance that you're using.

### Puller
On the non-compromised machine...

To get a sense of the options available to you:
```
python3 results-analyzer.py --help
Usage: results-analyzer.py [OPTIONS] COMMAND [ARGS]...

  Example: python3 results-analyzer.py --url="https://<domain-of-Assemblyline-
  instance>" --username="<user-name>" --apikey="<api-key-name>:<key>"
  --incident_num=123

Options:
  --url TEXT           The target URL that hosts Assemblyline.  [required]
  -u, --username TEXT  Your Assemblyline account username.  [required]
  --apikey TEXT        Your Assemblyline account API key. NOTE that this API
                       key requires read access.  [required]

  --min_score INTEGER  The minimum score for files that we want to query from
                       Assemblyline.

  --incident_num TEXT  The incident number for each file to be associated
                       with.  [required]

  --help               Show this message and exit.
```

Example Usage:
```
python3 results-analyzer.py --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="<api-key-name>:<key>" --incident_num=123
```

After a successful run, you should get some logs, followed by "All done!"

Now check the `report.txt` file that was created by the "Puller". This file will contain what files 
are safe/unsafe.

Act accordingly with this wealth of knowledge at your disposal.

