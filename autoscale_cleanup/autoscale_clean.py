import datetime
import requests
import random
import boto3
import time
import json
import sys
import re
import os
from dateutil.tz import tzutc
from botocore.exceptions import ClientError

class AutoScale_Clean:
  '''
  Tasks:
  -----
  [ ] - Gets EC2 instance instance targeted for cleanup
  [ ] - Delete instance information on Icinga2
  [ ] - Clean up Route53 (per instance entry)
  [ ] - Remove instance's salt-key from salt-master
  [ ] - Autoscaling complete lifecycle action
  [ ] - Add `plume_component_deployable` tag to terminated instance (set to false)
  [ ] - Deregister instance from IPA server
  '''

  def __init__(self, event_msg):
    '''
    AutoScale_Clean objects are instantiated with an event message (`event_msg`)
    passed in from a Cloudwatch event, triggering the Lambda code.  The kwargs key-value
    pairing, must be all environment variables gathered from user input in the
    Lambda.  These values contain access information and credentials for various
    host connections (Icinga2 master, SaltMaster).
    Instantiation also creates separate boto3 clients for ec2, autoscaling and route53.
    '''

    self.event_msg = event_msg
    self.vals_dict = {
      "msg_rcvd" : False,
      "msg_type" : None,
      "ipa_host" : "unknown"
    }
    self.ec2_client = boto3.client('ec2')
    self.s3_client = boto3.client('s3')
    self.r53_client = boto3.client('route53')
    self.asc_client = boto3.client('autoscaling')
    self.vals_from_message(self.event_msg)


  def assert_env_variables(self):
    '''
    Confirms that the class has access to all necessary env
    variables provided from the Lambda function.
    -
    Return: <None>
    '''

    required_keys = [
      "icinga_url",
      "icinga_user",
      "icinga_pw",
      "salt_api_user",
      "salt_api_pw",
      "salt_master",
      "salt_api_port",
      "salt_protocol"
    ]
    if self.vals_dict['ipa_host'] != 'unknown':
      required_keys.extend(
        [
          "ipa_host",
          "ipa_user",
          "ipa_pw"
        ]
      )

    for key in required_keys:
      if key not in self.vals_dict.keys():
        print("[Error]: !!!{} key missing from instantiation / environment variables; Exiting".format(key))
        sys.exit(0)


  def credentials_from_s3(self):
    '''
    Per EC2 instance hostname, function parses corresponding deployment
    specific credentials and hostnames.
    -
    Return: <None>, adds entries to self.vals_dict.
    '''

    ##Will need to determine a programmatic way to determine which file to parse
    #all dev infrastructure will utilize the same hosts and credentials

    print("\n\nGathering environment specific credentials per host from S3 bucket {}".format(os.environ['s3_bucket']))

    if self.vals_dict['version'] == 'V1':
      s3_credential_file = '{s3_subfolder}/ubuntu.{region}.{environment}.{deployment}.json'.format(**self.vals_dict)
    else: #denotes V2 namespace
      print("[Info]: V2 namespace discovered for host")
      s3_credential_file = '{s3_subfolder}/ubuntu.{datacenter}.{environment}.{sphere}.json'.format(**self.vals_dict)

    #account for infrastructure in dev; using the same file (<region>.dev.development.json) across all deployments
    if self.vals_dict['tld'] == 'plume.tech':
      if self.vals_dict['version'] == 'V1':
        s3_credential_file = '{s3_subfolder}/ubuntu.{region}.dev.development.json'.format(**self.vals_dict)
      else:
        s3_credential_file = '{s3_subfolder}/ubuntu.{datacenter}.dev.development.json'.format(**self.vals_dict)

    print("Seeking file {}".format(s3_credential_file))
    try:
      obj = self.s3_client.get_object(Bucket=self.vals_dict['s3_bucket'],
                                    Key='{}'.format(s3_credential_file))
    except ClientError:
      print("[Error]: !!! Failed to connect to S3 bucket, check IAM permissions for Lambda in accessing {}".format(os.environ['s3_bucket']))
      exit()

    credentials = json.loads(obj['Body'].read())
    icinga_creds, salt_creds = credentials['icinga2'], credentials['salt']

    if credentials.has_key('ipa'):
      self.vals_dict['ipa_host'] = "known"
      ipa_creds = credentials['ipa']

    def creds_update(creds_dict, service_name):
      '''
      Updates `self.vals_dict` with pertinent service
      credentials, prints success or error msg to stdout
      '''

      print("Updating {} credentials values from file".format(service_name))
      if service_name == 'Icinga2':
        self.vals_dict.update(
          {
            "icinga_url" : creds_dict['hostname'],
            "icinga_user" : creds_dict['director_user'],
            "icinga_pw" : creds_dict['director_pass']
          }
        )
      elif service_name == 'Salt':
        self.vals_dict.update(
          {
            "salt_api_user" : creds_dict['username'],
            "salt_api_pw" : creds_dict['password'],
            "salt_master" : creds_dict['hostname'],
            "salt_api_port" : creds_dict['port'],
            "salt_protocol" : creds_dict['protocol']
          }
        )
      elif service_name == 'IPA':
        self.vals_dict.update(
          {
            "ipa_host" : creds_dict['satellites'].split()[0],
            "ipa_user" : creds_dict['username'],
            "ipa_pw" : creds_dict['password']
          }
        )

    function_tuples = [(icinga_creds, "Icinga2"),
                       (salt_creds, "Salt")
    ]
    if self.vals_dict['ipa_host'] != 'unknown':
      function_tuples.append((ipa_creds, "IPA"))

    for _tuple in function_tuples:
      creds_update(*_tuple)


  def vals_from_message(self, message_body):
    '''
    Obtains the target terminated node from the
    autoscale event.  Queries the Cloudwatch message
    parsing json output.  Adds necessary values to
    the instance's `vals_dict`.
    -
    Return: <None>, adds entries to self.vals_dict.
    '''

    print("[Info]: Deployment package updated 01/05/19")
    parse_msg = "\n\nParsing values from Cloudwatch message per termination event"
    print("\n{}".format(parse_msg))
    for i in range(3):
      print("=" * len(parse_msg))

    print(message_body)
    print("\n\n")

    #determine whether this is an Autoscale, or Spot-instance termination
    if message_body['source'] == 'aws.autoscaling':
      self.vals_dict['msg_type'] = 'autoscale'
      self.vals_dict['autoscale_group'] = message_body['detail']['AutoScalingGroupName']
      self.vals_dict['lifecycle_hook'] = message_body['detail']['LifecycleHookName']
      self.vals_dict['autoscale_token'] = message_body['detail']['LifecycleActionToken']
      instance_id = message_body['detail']['EC2InstanceId']
    else:
      self.vals_dict['msg_type'] = 'spot_instance'
      instance_id = message_body['detail']['instance-id']

    self.vals_dict['msg_rcvd'] = True

    #add the FQDN to vals_dict (to be used in Saltmaster and Icinga deletes)
    try:
      print("[Info]: Attempting connection to ec2 client, if Lambda times out: check VPC config")
      ec2_response = self.ec2_client.describe_instances(
        Filters=[
          {
            'Name':'tag-key',
            'Values': [
              'Name'
            ]
          }
        ],
        InstanceIds=[
          instance_id
        ],
        DryRun=False
      )
    except ClientError:
      print("[Error]: !!!Failed to gather instance details per {}; Exiting".format(instance_id))
      sys.exit(0)
    print("[Info]: Successfully gathered data from ec2 client, VPC config is correct\n\n")

    if ec2_response['Reservations']:
      tag_level = ec2_response['Reservations'][0]['Instances'][0]['Tags']
      tld = [entry['Value'] for entry in tag_level if entry['Key'] == 'tld'][0]
      try:
        hostname = [entry['Value'] for entry in tag_level if entry['Key'] == 'Name'][0]
      except:
        hostname = [entry['Value'] for entry in tag_level if entry['Key'] == 'name'][0]
        hostname = [entry for entry in hostname if entry][0]
        if not hostname:
          print("[Error]: !!!Failed to parse hostname from EC2 tags; exiting")
          exit()
      environment = [entry['Value'] for entry in tag_level if entry['Key'] == 'environment'][0]
      #the cloud tag determines whether the host is named per V1 or V2
      cloud = [entry['Value'] for entry in tag_level if entry['Key'] == 'cloud']
      if cloud: #indicates V1 namespace
        cloud = cloud[0]
        region = [entry['Value'] for entry in tag_level if entry['Key'] == 'region'][0]
        deployment = [entry['Value'] for entry in tag_level if entry['Key'] == 'deployment'][0]
        self.vals_dict.update(
          {
            "region" : region,
            "version" : "V1",
            "deployment" : deployment
          }
        )
      else: #indicates V2 namespace
        try:
          datacenter = [entry['Value'] for entry in tag_level if entry['Key'] == 'datacenter'][0]
          sphere = [entry['Value'] for entry in tag_level if entry['Key'] == 'sphere'][0]
        except:
          print("[Error]: Failed to gather required sphere or datacenter values per V2 namespace host")
          exit()

        #Kappa/Sigma have independent Lambdas triggered by the same Cloudwatch events
        #If Lambda has been triggered for an instance from another sphere: exit()
        if os.environ.has_key('sphere'):
          if os.environ['sphere'] != sphere:
            exit_msg = "[Info]: Lambda from {} sphere has been triggered".format(os.environ['sphere'])
            exit_msg += " for instance from {} sphere; exiting".format(sphere)
            print(exit_msg)
            exit()

        self.vals_dict.update(
          {
            "datacenter" : datacenter,
            "version" : "V2",
            "sphere" : sphere
          }
        )
    else:
      print("[Error]: !!!Failed to parse EC2 hostname from instance id; Exiting")
      exit()

    self.vals_dict.update(
      {
        "s3_subfolder" : os.environ['s3_subfolder'],
           "s3_bucket" : os.environ['s3_bucket'],
         "environment" : environment,
         "instance_id" : instance_id,
            "hostname" : hostname,
                 "tld" : tld
      }
    )

    #gather necessary credentials from S3 bucket
    print("[Info]: Pulling credentials from S3 bucket {}".format(self.vals_dict['s3_bucket']))
    self.credentials_from_s3()
    #confirm that all necessary environment variables have been gathered from Lambda
    self.assert_env_variables()

    for key, val in self.vals_dict.items():
      if not self.vals_dict[key]:
        print("[Error]: !!!Failed to parse {} from Cloudwatch message; exiting".format(key))
        sys.exit(0)
      else:
        if key in ['icinga_pw', 'ipa_pw', 'salt_api_pw']:
          print("Value for key {} == {}".format(key, ''.join(['*' for _char in val])))
        else:
          print("Value for key {} == {}".format(key, val))
    print("[Info]: Global values dictionary updated after successful message parsing")
    if os.environ['TestingFlag'] == 'on':
      print("[Testing]: TestingFlag triggered; exiting")
      exit(0)


  def update_instance_tags(self):
    '''
    Adds tag `plume_component_deployable:false` to terminated instance
    -
    Return: <None>
    '''

    print("\n\nAdding autoscale tag to instance {}".format(self.vals_dict['instance_id']))
    tag_response = self.ec2_client.create_tags(
      DryRun=False,
      Resources=[
        self.vals_dict['instance_id']
      ],
      Tags=[
        {
          'Key' : 'plume_component_deployable',
          'Value' : 'false'
        }
      ]
    )
    if tag_response['ResponseMetadata']['HTTPStatusCode'] == 200:
      print("[Info]: Successfully tagged terminated instance {}".format(self.vals_dict['instance_id']))
    else:
      print("[Error]: !!!Failed to tag instance {}".format(self.vals_dict['instance_id']))


  def delete_from_icinga(self, hostname):
    '''
    Removes the host from the Icinga2 master
    -
    Return: <None>
    '''

    print("\n\nAttempting to delete host record for {} from Icinga2 master".format(hostname))

    protocol = 'http'
    http_header = {'Accept':'application/json'}
    host_components = hostname.split('.')
    host_base = host_components.pop(0)

    host_names = [host_base]
    for component in host_components:
      host_base += '.' + component
      host_names.append(host_base)

    host_urls = ["{}://{}/icingaweb2/director/host?name={}".format(protocol, self.vals_dict['icinga_url'], name) for name in host_names]

    response_map = list(map(lambda url:
                              {
                                url:requests.get(url,
                                auth=(self.vals_dict['icinga_user'],
                                      self.vals_dict['icinga_pw']),
                                headers=http_header,
                                verify=False).status_code
                              },
                              host_urls
                            )
                        )

    response_url = [entry.keys()[0] if entry.values()[0] == 200 else None for entry in response_map]
    response_url = [entry for entry in response_url if entry]
    if response_url:
      icinga_host_url = response_url[0]
    else:
      icinga_host_url = response_url

    #check initial connection to Icinga2 master, per hostname endpoint
    if icinga_host_url:
      print("[Info]: Host record for {} found on Icinga2 master, deleting from master".format(hostname))
      delete_response = requests.delete(icinga_host_url,
        auth=(self.vals_dict['icinga_user'], self.vals_dict['icinga_pw']),
        headers=http_header,
        verify=False
      )
      #confirm successful deletion of host record from Icinga2 master
      if delete_response.status_code == 200:
        print("[Info]: Successfully deleted {} record from Icinga2 master".format(hostname))
        #send a POST to the Icinga2 server, acting as a commit
        post_url = "{}://{}/icingaweb2/director/config/deploy".format(protocol, self.vals_dict['icinga_url'])

        #if many autoscaled instances terminate simultaneously, multiple config deploys at once can trigger API issues
        #set random timeout to avoid overwhelming the API's config deploy endpoint
        time.sleep(random.randrange(0,30,2))

        commit_response = requests.post(post_url,
          auth=(self.vals_dict['icinga_user'], self.vals_dict['icinga_pw']),
          headers=http_header,
          verify=False
        )
        if commit_response.status_code == 200:
          print("[Info]: Successful commit to Icinga2 master after record deletion for {}".format(hostname))
        else:
          print("[Error]: !!!Received {} error in posting commit to Icinga2 master, delete may not be permanent".format(str(commit_response.status_code)))
      #delete failure
      else:
        print("[Error]: !!!Received {} error attempting to delete host from Icinga2 master; Failed".format(str(delete_response.status_code)))
    #Icinga2 connection failure per hostname endpoint (host record does not exist on master)
    else:
      print("[Error]: !!!Receieved {} error calling Icinga2 master for {}; no record to delete".format("404", hostname))


  def clean_route53(self, hostname):
    '''
    Clears the route53 entry in the specific hosted zone of
    the host's A record.  Utilizes the target instance's
    hostname and private IP address, gathered from `vals_dict`
    -
    Return: <None>
    '''

    print("\n\nDeleting route53 record entry for host {}".format(hostname))
    zone = hostname[hostname.index('.')+1:]
    zone_response = self.r53_client.list_hosted_zones_by_name(
      DNSName=zone
    )
    hosted_zone = zone_response['HostedZones'][0]['Id']
    hosted_zone = re.sub(r'\/.*\/','',hosted_zone)

    ip_response = self.r53_client.list_resource_record_sets(
      HostedZoneId=hosted_zone,
      StartRecordName=hostname + '.',
      StartRecordType='A'
    )
    private_ip = None
    try:
      records = ip_response['ResourceRecordSets']
      target_record = [record for record in records
                       if record['Name'] == hostname + '.'][0]
      private_ip = target_record['ResourceRecords'][0]['Value']
    except:
      print("[Error]: !!!Failed to parse ip address from Route53 record")

    #figure out a way to parse TTL from instance description
    if private_ip:
      record_response = self.r53_client.change_resource_record_sets(
          HostedZoneId=hosted_zone,
          ChangeBatch={
            'Comment' : 'autoscale host termination event',
            'Changes' : [
              {
                'Action' : 'DELETE',
                'ResourceRecordSet' : {
                'Name' : hostname + '.',
                'Type' : 'A',
                'TTL' : 300,
                'ResourceRecords' : [
                  {
                    'Value' : private_ip
                  }
                ]
              }
            },
          ]
        }
      )
      if record_response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print("[Info]: Successfully deleted route53 A record for {}".format(hostname))
      else:
        print("[Error]: !!!Failed to delete route53 A record for {}".format(hostname))


  def clean_salt_keys(self, hostname):
    '''
    Deletes salt-key from terminated host from the Saltmaster
    -
    Return: <None>
    '''

    print("\n\nDeleting salt-key for host {}".format(hostname))
    protocol = self.vals_dict['salt_protocol']
    salt_url = '{}://'.format(protocol) + self.vals_dict['salt_master'] + ":" + str(self.vals_dict['salt_api_port'])
    salt_session = requests.Session()

    salt_return = salt_session.post(
      salt_url + "/login",
      json={
        'username' : self.vals_dict['salt_api_user'],
        'password' : self.vals_dict['salt_api_pw'],
           'eauth' : 'pam'
      }
    ).json()

    salt_token = salt_return['return'][0]['token']

    salt_delete = salt_session.post(
      salt_url,
      json=[
        {
          'X-Auth-Token' : salt_token,
                'client' : 'wheel',
                   'fun' : 'key.delete',
                 'match' : hostname
        }
      ]
    ).json()

    if salt_delete['return'][0]['data']['success']:
      print("[Info]: Successfully deleted salt-key for {}".format(hostname))
    else:
      print("[Error]: !!!Failed to delete salt-key for {}".format(hostname))


  def complete_lifecycle_action(self):
    '''
    Completes lifecycle action event
    -
    Return: <None>
    '''

    print("\n\nSending completion notification for lifecycle action")
    try:
      autoscale_response = self.asc_client.complete_lifecycle_action(
        LifecycleHookName=self.vals_dict['lifecycle_hook'],
        AutoScalingGroupName=self.vals_dict['autoscale_group'],
        LifecycleActionResult='CONTINUE',
        LifecycleActionToken=self.vals_dict['autoscale_token'],
        InstanceId=self.vals_dict['instance_id']
      )
      print("[Info]: Successful completion of lifecycle event")
    except ClientError:
      print("[Error]: !!!Failed to find and complete lifecycle action")


  def ipa_deregister(self, hostname):
    '''
    Deregisters host from IPA server
    -
    Return: <None>
    '''

    requests.packages.urllib3.disable_warnings()
    print("\n\nAttempting to derigister {} from IPA server".format(hostname))
    protocol = 'https'
    host_con = '{}://{}/ipa/'.format(protocol, self.vals_dict['ipa_host'])
    session = requests.Session()
    try:
      ipa_response = session.post('{}session/login_password'.format(host_con),
        params="",
        data={
          'user':self.vals_dict['ipa_user'],
          'password':self.vals_dict['ipa_pw']
        },
        verify=False,
        headers={
          'Content-Type':'application/x-www-form-urlencoded',
          'Accept':'application/json'
        }
      )
    except Exception as e:
      print("[Error]: !!!Failed to connect to IPA sattelite {}".format(self.vals_dict['ipa_host']))
      print(str(e))

    #test for successful connection to the server, failure will yield a 400||401 error
    if hasattr(ipa_response,'status_code') and ipa_response.status_code == 200:
      print("Established connection w/ satellite {}".format(self.vals_dict['ipa_host']))
      header = {
        'referer' : host_con,
        'Content-Type':'application/json',
        'Accept':'application/json'
      }
      #seek out the host on the IPA server
      find_host = session.post('{}session/json'.format(host_con),
        headers=header,
        data=json.dumps(
          {
            'id': 0,
            'method': 'host_find',
            'params': [
              [],
              {
                "fqdn": hostname
              }
            ]
          }
        ),
        verify=True
      )
      #host found and registered in IPA server
      if find_host.json()['result']['count'] != 0:
        print("[Info]: Found host {} on IPA server, attempting deregistration".format(hostname))

        delete_host = session.post('{0}session/json'.format(host_con),
          headers=header,
          data=json.dumps(
            {
              'id': 0,
              'method': 'host_del',
              'params': [
                [
                  [hostname]
                ],
                {
                }
              ]
            }
          ),
          verify=False
        )
        #test returned json for successful deletion status message
        if not delete_host.json()['error']:
          print("[Info]:  Successfully deleted host {} from IPA server".format(hostname))
        #print failure message, and error gathered from IPA server
        else:
          print("[Error]: !!!Failed to delete existing host {} on IPA server".format(hostname))
          try:
            print(delete_host.json()['error'])
          except:
            print("[Error]:  !!!Failed to gather error mesage from IPA server")
      #host not found
      else:
        print("[Error]: !!!Host {} not found on IPA server, nothing to remove".format(hostname))
    #failure to connect to IPA server
    else:
      print("[Error]: !!!Attempted connection to IPA server returned error")


  def execute_cleanup(self, hostname):
    '''
    Executes all functions necessary for terminated host
    cleanup triggered by the Lambda event.
    -
    Return: <None>
    '''

    #env key TestingFlag set to `on` will merely display key:val pairs
    #used as a means of assuring Lambda has access to neccessary credentials

    self.update_instance_tags()
    if self.vals_dict['msg_type'] == 'autoscale':
      self.complete_lifecycle_action()
    self.delete_from_icinga(hostname)
    self.clean_route53(hostname)
    self.clean_salt_keys(hostname)
    if self.vals_dict['ipa_host'] != 'unknown':
      self.ipa_deregister(hostname)


def lambda_handler(event, context):
  title_string = "[Info]: Event message printed below:"
  print("{}\n{}".format(title_string, "=" * len(title_string)))
  print(event)
  cleaner = AutoScale_Clean(event)
  #iterate through all cleanup functions (other than delete_sqs_msg)
  cleaner.execute_cleanup(cleaner.vals_dict['hostname'])


################################################################################
################################################################################
'''
if __name__=="__main__":
  #testing in dev
  print("This shouldn't be invoked by Lambda function")
  with open('eventmsg', 'r') as em:
    msg = json.loads(em.read())
  os.environ['s3_bucket'] = 'plume-global-ubuntu-mirrors-eu-central-1'
  os.environ['s3_subfolder'] = 'plume-bootstrap-config'
  os.environ['TestingFlag'] = 'on'
  os.environ['sphere'] = 'sigma'
  lambda_handler(msg, None)
'''
