from snaptools import *

def lambda_handler(event, context):
  for environ in os.environ:
    if environ.startswith('Instance'):
      snap = SnapTools(os.environ[environ], local=False)
      snap.snapshot_master(interactive=True, dry_run=False, deletes=True, printing=True)
 
