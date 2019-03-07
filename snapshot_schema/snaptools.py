import os
import re
import sys
import boto3
import datetime
from dateutil import tz
from dateutil.tz import tzlocal
from botocore.exceptions import ClientError


class SnapTools:
  '''
  Options:
  =======
  Can be run by accessing a user's loaded AWS credentials:
  -------------------------------------------------------
  ./snaptools.py --hostname jira-development-01.inf.us-west-2.aws.plume.tech

  Or on a server, with an included yaml file containing credentials:
  -----------------------------------------------------------------
  ./snaptools.py --hostname jira-development-01.inf.us-west-2.aws.plume.tech
                 --settings settings.yaml
  '''
  def __init__(self, ec2_instance, local=False):
    self.client = SnapTools.ec2_client(local)
    self.instance = ec2_instance


  def instance_vals(self):
    '''
    Returns all available values from boto3 ec2 `describe_instance`
    function for `self.instance`.
    Produces a dictionary, whose keys are:
      - `Reservations`
      - `ResponseMetadata`
    '''
    ec2_dict = self.client.describe_instances(
                 Filters=[
                   {
                     'Name':'tag:Name',
                     'Values':['{}'.format(self.instance)
                     ]
                   }
                 ]
               )
    try:
      instance_data = ec2_dict['Reservations'][0]['Instances'][0]
    except IndexError:
      print("EC2 instance is not reachable; exiting")
      exit()

    metadata = ec2_dict['ResponseMetadata']

    ec2_vals = {'volumes': instance_data['BlockDeviceMappings'],
                'instance_id': instance_data['InstanceId'],
                'tags': instance_data['Tags']
    }

    return ec2_vals


  def val_parser(self):
    '''
    Function parses out necessary Tag values from the returned
    dictionary gathered by the `instance_vals` function
    Returns a dictionary of values to be used for string formatting
    '''
    ec2_data = self.instance_vals()
    name_dict = {}
    name_tags = ['host_id', 'component', 'deployment', 'environment']

    #gather instance tag values per `name_tags` list
    for item in ec2_data['tags']:
      for entry in name_tags:
        if item['Key'].upper() == entry.upper():
          name_dict[entry] = item['Value']

    #create a blank value dict entry if tag value missing
    for entry in name_tags:
      if entry not in name_dict:
        name_dict[entry] = ''

    name_dict['time_stamp'] = str(datetime.datetime.now().isoformat())
    return name_dict


  def ebs_data(self):
    '''
    Function parses ebs volume data from returned dictionary
    gathered by the `instance_vals` function
    Returns a dictionary containing info pertaining to EBS volumes
    attached to `self.instance`
    '''
    ebs_data = self.instance_vals()['volumes']
    ebs_dict = {item['DeviceName']:item['Ebs']['VolumeId'] for item in ebs_data}

    return ebs_dict


  def mk_snapshot(self, partition_name, volume_id, dry_run=False):
    '''
    Creates a snapshot of the given EBS volume
    per `volume_id` argument

    The `dry_run` option arg is primarily to test the naming
    convention of the snapshot to be created.
    If set to `True` (in the calling `snapshot_master` function,
    the intended snapshot to be created will have it`s name displayed).
    '''
    tag_name = True
    name_vals = self.val_parser()
    name_vals['volume'] = volume_id
    name_vals['partition'] = partition_name
    name_vals['instance'] = self.instance

    snapshot_name = '{instance}:{partition}'.format(**name_vals)
    name_vals['snapshot_name'] = snapshot_name
 

    msg = "\nCreating snapshot '{snapshot_name}':".format(**name_vals)
    print(msg + '\n' + '#' * len(msg))
    msg = "    Ec2 Instance: {instance}\n".format(**name_vals)
    msg += "    Partition: {partition}\n".format(**name_vals)
    msg += "    Volume_ID: {volume}\n".format(**name_vals)
    print(msg)

    self.client.create_snapshot(
        Description='{volume}_{time_stamp}'.format(**name_vals),
        VolumeId='{}'.format(volume_id),
        TagSpecifications=[
          {
            'ResourceType':'snapshot',
            'Tags': [
              {
                'Key': 'Name',
                'Value': '{snapshot_name}'.format(**name_vals)
              },
              {
                'Key': 'Volume_Id',
                'Value': '{volume}'.format(**name_vals)
              },
              {
                'Key': 'Time_Stamp',
                'Value': '{time_stamp}'.format(**name_vals)
              },
              {
                'Key': 'costcenter',          
                'Value': 'dev'
              }
            ]
          },
        ],
      DryRun=False
    )



  def snapshot_master(self, interactive=False, dry_run=False, deletes=False, printing=False):
    '''
    The main gateway function for creating snapshots per
    the object's ec2-instance EBS volumes
    Calls functions:
      - `val_parser` (for string formatting)
      - `ebs_data` (to target volumes and feed data)
      - `mk_snapshot` (called per ebs volume id)
    If `interactive` is set to True:
      - The function will display intended values and
        prompt user for confirmation of snapshot creation
        per volume attached to instance
    If `dry_run` is set to True:
      - The function will refrain from creating snapshots
    If `deletes` is set to True:
      - The function will trigger the classes' `del_snapshots`
        function.  The snapshots associated with the classes`
        EC2 instance EBS volumes will will be deleted according
        to the current snapshot deletion / preservation schema.
    '''
    ebs_dict = self.ebs_data()
    for key in ebs_dict:
      self.mk_snapshot(key, ebs_dict[key], dry_run)

    if deletes:
      for key in ebs_dict:
        self.del_snapshots(ebs_dict[key], printing=printing)


  @classmethod
  def usage(cls, error=False):
    '''
    Displays proper input parameters
    given either `--help` argument
    or incorrect/insufficient arg input
    '''
    if error:
      print("\nError: incorrect argument usage")

    helpstring = '''
    Input errors: Please run program per documentation
    Options:
    =======
    Can be run by accessing a user's loaded AWS credentials:
    -------------------------------------------------------
    ./snaptools.py --hostname jira-development-01.inf.us-west-2.aws.plume.tech

    Or on a server, with an included yaml file containing credentials:
    -----------------------------------------------------------------
    ./snaptools.py --hostname jira-development-01.inf.us-west-2.aws.plume.tech
                   --settings settings.yaml
    '''
    print(helpstring)
    exit()


  @classmethod
  def arg_parse(cls, error=False):
    '''
    Asserts argument inputs allowing for class
    implementation based on sys.argv inputs
    Allowed args:
      --hostname <instance-hostname>
      --settings <settingsFile.yaml>
      --help
    '''
    arg_dict = {
                'local':False
    }
    if '--help' in sys.argv or '--hostname' not in sys.argv: SnapTools.usage()
    for entry in sys.argv:
      if entry.startswith('--') and entry not in ['--settings', '--hostname']:
        SnapTools.usage(error=True)

    #could check health and reachability of the instance
    arg_dict['instance'] = re.sub(r'.*--hostname\s*(\S*).*', r'\1', ' '.join(sys.argv[:]))
    #could check correct formatting of yaml_file
    if '--settings' in sys.argv:
      arg_dict['yaml_file'] = re.sub(r'.*--settings\s*(\S*).*', r'\1', ' '.join(sys.argv[:]))
      arg_dict['local'] = True

    return arg_dict


  @classmethod
  def ec2_client(cls, local=False):
    if local:
      #add assert statements here:
      '''
      yaml file needs to be formatted:
      -------------------------------
      component:
        aws_access_key: ''
        aws_secret_key: ''
        region: ''

        - check for a settings.yaml file
        - confirm that the component dict
          is working correctly
      '''
      print("local has been activated")
      exit()
      #should call argparse to get yamlFile
      #should parse out component name from yamlFile
      with open(yamlFile) as yf:
        settings = yaml.load(yf)

      access_key = settings[component]['aws_access_key']
      secret_key = settings[component]['aws_secret_key']
      region = settings[component]['region']

      ec2_con = boto3.client('ec2',
                  aws_access_key_id=access_key,
                  aws_secret_access_key=secret_key,
                  region_name=region
                )
    else:
      ec2_con = boto3.client('ec2')

    return ec2_con


  def del_snapshots(self, volume_id, printing=False):
    '''
    Deletes archived snapshots per volume id
    All snapshots < 31 days old will be preserved
    For all snapshots:
      * 1-2 months : 2 snapshots preserved per day
      * 2-3 months : 1 snapshot preserved per day
      * 3-4 months : 1 snapshot preserved per day
      * 4-5 months : 1 snapshot preserved per day
      * 5-6 months : 1 snapshot preserved per day
      * > 6 months : 1 snapshot preserved
    '''

    snapshots = [ snapshot for snapshot in self.client.describe_snapshots()['Snapshots']
                  if snapshot['VolumeId'] == volume_id ]
    dt = [num for num in datetime.datetime.now().timetuple()[:6]]
    local_time = datetime.datetime(dt[0], dt[1], dt[2], dt[3], dt[4], dt[5], tzinfo=tz.tzlocal())

    #gather a list of snapshots within the last 30 days (all will be preserved)
    def snap_gather(day_start, day_end=0):
      '''
      Creates lists of snapshots per volume id
      will create a list within time window
      indicated by range between `day_start` & `day_end`
      '''

      #gather a list of all snapshots > 6 months old
      if day_start == 181:
        snap_list = [(snapshot['SnapshotId'], snapshot['VolumeId'], snapshot['StartTime'])
                      for snapshot in snapshots
                      if (local_time - snapshot['StartTime']).days >= day_start ]
      else: #snap lists > 6 months will capture snaps withing start and end range
        snap_list = [(snapshot['SnapshotId'], snapshot['VolumeId'], snapshot['StartTime'])
                     for snapshot in snapshots
                     if (local_time - snapshot['StartTime']).days >= day_start
                     and (local_time - snapshot['StartTime']).days < day_end + 1 ]

      return snap_list

    #create a list of snapshot sub-lists per timestamps
    snap_dict = {key:snap_gather(*val[:]) for key,val in
                 {"0-30":[0, 30], "31-60":[31, 60], "61-90":[61, 90], "91-120":[91, 120],
                  "121-150":[121, 150], "151-180":[151, 180], "181+":[181]}.items()}

    snap_dict = {volume_id+":__"+key:val for key,val in snap_dict.items() if val}

    #deleting all but 1 snapshots > 6 months old:
    def del_snap(snapshot_id):
      '''
      Deletes a target snapshot id
      '''
      try:
        self.client.delete_snapshot(SnapshotId=snapshot_id)
      except ClientError:
        print("{} is in use; skipping delete".format(snapshot_id))
  
    try:      
      if snap_dict[volume_id+":__181+"]:
        print("Deleting all but 1 snapshot > 6 months old")
        print("Snapshot to be preserved:" + "\n" + "#" * 26)
        print(snap_dict[volume_id+":__181+"][0])
        snap_dict[volume_id+":__181+"].remove(snap_dict[volume_id+":__181+"][0])
        #confirm list has contents after removal of single snapshot
        if snap_dict[volume_id+":__181+"]:
          print("Snapshots to be deleted:" + "\n" + "#" * 24)
          for _tuple in snap_dict[volume_id+":__181+"]:
            print(_tuple)
            #delete snapshot
            if _tuple: del_snap(_tuple[0])
        del snap_dict[volume_id+":__181+"]
    except:
      print("For {}, no snapshots > 6 months old\n\n".format(volume_id))

    #create sub-groupings of snapshot lists per day within snap_dict
    day_groups = {}
    for snap in snap_dict:
      for _tuple in snap_dict[snap]:
        volday_string = "(" + str(_tuple[2].day) + ")_" + snap 
        if volday_string not in day_groups:
          day_groups[volday_string] = [_tuple]
        else:
          day_groups[volday_string].append(_tuple)

    #discard snap_dict
    del snap_dict
    
    for key in day_groups:
      grouping = key[key.index('__')+2:]
      if grouping == "0-30":
        header = "\n\n{}:{}--Preserving all snapshots".format(volume_id, grouping)
        print(header + "\n" + "-" * len(header))
        print("Snapshots to be preserved:" + "\n" + "#" * 26)
        for _tuple in day_groups[key]:
          print(_tuple)

      elif grouping == "31-60":
        header = "\n\n{}:{}--Preserving 2 snapshots per day".format(volume_id, grouping)
        print(header + "\n" + "-" * len(header))
        print("Snapshots to be preserved:" + "\n" + "#" * 26)
        print(day_groups[key][0], day_groups[key][len(day_groups[key])/2])
        day_groups[key].remove(day_groups[key][0])
        if day_groups[key]:
          day_groups[key].remove(day_groups[key][len(day_groups[key])/2])
        print("Snapshots to be deleted:" + "\n" + "#" * 24)
        for _tuple in day_groups[key]:
          print(_tuple)
          #delete snapshot
          if _tuple: del_snap(_tuple[0])
 
      else:
        header = "\n\n{}:{}--Preserving 1 snapshot per day".format(volume_id, grouping)
        print(header + "\n" + "-" * len(header))
        print("Snapshots to be preserved:" + "\n" + "#" * 26)
        print(day_groups[key][0])
        day_groups[key].remove(day_groups[key][0])
        #remove those from day_groups[key]
        print("Snapshots to be deleted:" + "\n" + "#" * 24)
        for _tuple in day_groups[key]:
          print(_tuple)
          #delete snapshot
          if _tuple: del_snap(_tuple[0])
          

if __name__=="__main__":
  args =  SnapTools.arg_parse()
  snap = SnapTools(args['instance'], local=args['local'])
  snap.snapshot_master(interactive=True, dry_run=False, deletes=True, printing=True)

  ###snapshots can be deleted by instance; run program as ./snaptools.py --instance None
  ###uncomment command below and feed in a volume id
  ###delete per instance argument's attached volumes; comment out out `snapshot_master` above to foregoe snap creation
  '''
  for vol in snap.ebs_data():
    snap.del_snapshots(snap.ebs_data()[vol], printing=True)
  '''
