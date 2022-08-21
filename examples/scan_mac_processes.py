import traceback
import hashlib
import os
import argparse

from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis
import psutil


def scan(api_key):
    scanned_files = set()
    api.set_global_api(api_key)
    for proc in psutil.process_iter():
        try:
            process_path = proc.exe()
            if process_path in scanned_files:
                print('{} already scanned'.format(process_path))
                continue
            elif not os.path.exists(process_path):
                print('{} does not exist'.format(process_path))
                continue

            scanned_files.add(process_path)
            sha256 = sha256sum(process_path)

            # check if hash already exists
            try:
                analysis = FileAnalysis.from_latest_hash_analysis(sha256, file_name=process_path)
            except Exception:
                analysis = None
            if analysis is None:
                analysis_op = FileAnalysis(file_path=process_path, file_name=process_path)
                print('uploading {}'.format(process_path))
                try:
                    analysis_op.send(wait=False, source='Mac scan')
                except Exception:
                    print('error scanning file, skipped {}'.format(proc.name()))
            else:
                # analyze again by hash to get an updated analysis
                try:
                    print('analyzing by hash {}'.format(process_path))
                    analysis_op = FileAnalysis(file_hash=sha256, file_name=process_path)
                    analysis_op.send(wait=False, source='Mac scan')
                except Exception:
                    print('error scanning hash, skipped {}'.format(proc.name()))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print('error in reading process, skipped {}'.format(proc.name()))
        except Exception:
            traceback.print_exc()


def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scan all running processes in Intezer")
    parser.add_argument("-k", "--apikey", help="Intezer API Key", required=True)

    args = parser.parse_args()
    scan(args.apikey)

    print('scan complete')
