#!/bin/bash

: '<create_snapshot_lambda.sh>
 - An automated process for implementing an EC2 snapshot creation/deletion schema
   as a Lambda function
 - Works in accordance with python module `snaptools.py`

   Main:
   ----
   [ ] - Creates single IAM role per environment (given Lambda and ec2 snapshot permissions)
         - Prompt the user to use existing role, or create new
   [ ] - Creates a lambda function for single EC2 hostname, using provided .zip file `mastersnaps.zip`
   [ ] - Creates a cloudwatch event, with a declared rate of frequency
   [ ] - Adds Cloudwatch permissions to the lambda function
   [ ] - Adds the Lambda function as a target to the Cloudwatch event

   Post:
   ----
   [ ] - Allows for invocation of the Lambda function from CLI
   [ ] - Allows for taredown/revert to undo all changes
         - Create a temporary file of variables created
<mklambda.>'


#Permissions data for IAM role:
policy=$(cat <<-"EOF"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "ec2:Describe*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSnapshot",
                "ec2:CreateNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteSnapshot",
                "ec2:CreateTags",
                "ec2:ModifySnapshotAttribute",
                "ec2:ResetSnapshotAttribute"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
)


#Policy file for creating role:
role=$(cat <<-"EOF"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)


helper(){
  : '<helper>
   - Prints argument input options per arg call
     or upon incorrect argument input
  <helper>'

  cat <<-EOF
  create_snapshot_lambda.sh:
  -------------------------

  REQUIREMENTS:
  ------------------------------------------------------------------------------------------
  ./create_snapshot_lambda.sh --hostname <ec2-hostnameName> --environment <environment-name>
  ------------------------------------------------------------------------------------------

  OPTIONAL:
  -------------------------------------------------------------------------------------------------------------
  ./create_snapshot_lambda.sh --role <IAM-role-name> --frequency <hours> --settings <file.<json|yaml>> --delete
  -------------------------------------------------------------------------------------------------------------

  --role:       If given, must be an IAM role with permissions similar to the JSON parameters
                in 'policy' variable above.
                If argument not given: a new IAM role for Lambda snapshot execution will be
                created for the environment.

  --frequency:  Default argument is 2.  Snapshots will run per this hourly argument.

  --settings:   Allows for AWS credentials to be provided from an included Yaml or json file.
                File name must end in .json or .yaml, and must be formatted appropriately.
                See function comment in read_creds() for formatting requirements.

  --delete:     !!!Warning!!! This is primarily used for tare-down after testing.  This will
                delete the targeted Lambda function created by variable name-space, as well
                as the IAM role and policy associated with the function.
EOF
  exit
}


read_creds(){
  : '<read_creds>
   - Gathers AWS credentials from an included Yaml or json file, following the `--settings` flag
   - !!!File name must have a `.yaml` or `.json` suffix

   - Yaml file must be of the format:
     -------------------------------
     snapshot-credentials:
       aws:
         credentials:
           aws_access_key_id: <access-key>
           aws_secret_access_key: <secret-key>
           region: <region-name>

     ###############################
     ###############################

     json file must be of the format:
     -------------------------------
     {
       "aws_access_key_id" : "<access-key>",
       "aws_secret_key_id" : "<secret-key>",
       "region" : "<region-name>"
     }

  <read_creds>'
  creds_file=${1}

     if [[ ${creds_file} =~ \.json ]]; then
    json_flag=true
  elif [[ ${creds_file} =~ \.yaml ]]; then
    json_flag=false
  else
    echo "${creds_file} is not a supported format!!!"
    exit 1
  fi

  if [[ ${json_flag} == true ]]; then
    echo "Reading json input"
    for arg in "aws_access_key_id" "aws_secret_access_key" "region";do
      case $arg in
        aws_access_key_id)
          export AWS_ACCESS_KEY_ID=$(cat settings.json | jq .aws_access_key_id | sed 's/"//g');;
        aws_secret_access_key)
          export AWS_SECRET_ACCESS_KEY=$(cat settings.json | jq .aws_secret_access_key | sed 's/"//g');;
        region)
          export AWS_DEFAULT_REGION=$(cat settings.json | jq .region | sed 's/"//g');;
      esac
    done

  elif [[ ${json_flag} == false ]]; then
    echo "Reading Yaml input"
    export AWS_ACCESS_KEY_ID=$(grep 'access' ${creds_file} | awk -F'access: ' '{print $2}')
    export AWS_SECRET_ACCESS_KEY=$(grep 'secret' ${creds_file} | awk -F'secret: ' '{print $2}')
    export AWS_DEFAULT_REGION=$(grep 'region' ${creds_file} | awk -F'region: ' '{print $2}')
  fi

  for i in ${AWS_ACCESS_KEY_ID} ${AWS_SECRET_ACCESS_KEY} ${AWS_DEFAULT_REGION};do
      [[ ${i} == '' ]] && echo "!!!${creds_file} has failed to provide credentials; exiting" && exit 1
  done
  : 'COMMENT
  echo "End of case statements:"
  echo ${AWS_ACCESS_KEY_ID}
  echo ${AWS_SECRET_ACCESS_KEY}
  echo ${AWS_DEFAULT_REGION}
  exit
  COMMENT '
}

get_args(){
  : '<get_args>
   - Gathers argument inputs and creates necessary variables
     - `hostname`
     - `component` (parsed from hostname via regex)
     - `environment`
     - `role_name`
  <get_args>'

  hostname=''
  environment=''
  role_name=''
  create_role=true
  delete=false
  frequency=2
  epoch=$(date +"%s")

  counter=0
  for arg in "$@";do
    arrval="${@:$((counter+2)):1}"
    case "$arg" in
      --hostname)
        hostname+="${arrval}";;
      --environment)
        environment="${arrval}";;
      --frequency)
        frequency="${arrval}";;
      --role)
        role_name="${arrval}"
        create_role=false;;
      --settings)
        creds_file="${arrval}"
        read_creds ${creds_file};;
      --delete)
        delete=true;;
      --help)
        helper;;
    esac
    (( counter++ ))
  done


  #`hostname` and `environment` are required args
  [[ -z "${hostname}" ]] || [[ -z "${environment}" ]] && helper

  #component is parsed by regex from hostname
  component=$(echo ${hostname} | sed 's/\([a-zA-Z0-9]*\)-.*/\1/')

  #create new role name, if one was not given as argument
  [[ -z "${role_name}" ]] && role_name="plume-${environment}-snapshot-lambda-role"
  policy_name="plume-${environment}-snapshot-lambda-policy"


  : 'COMMENT
  echo "hostname = ${hostname}"
  echo "environment = ${environment}"
  echo "frequency = ${frequency}"
  echo "role = ${role_name}"
  echo "component = ${component}"
  COMMENT'
}
get_args "$@"


create_IAM(){
  : '<create_IAM>
    - if argument `--create-role` is given at program level:
      script will create a new role and policy per environment
      argument to administer the new Lambda function
  <create_IAM>'

  echo "${policy}" > snapPolicy.json
  echo "${role}" > snapRole.json
  for file in snapPolicy.json snapRole.json; do
    chmod a+r ${file}
  done


  #test to see whether or not role is already created
  aws iam get-role --role-name ${role_name} > /dev/null 2>&1

  if [[ $? == 0 ]]; then
    delim=''
    for ((i=0;i<64;i++));do
      delim+='#'
    done
    echo -e "\n${delim}  \n  IAM role ${role_name} already exists"
    echo "  Please confirm that role has proper Lambda and EC2 permissions"
    echo -e "  Role will be applied to Lambda function\n${delim}\n"
  else
    #create role:
    aws iam create-role --role-name ${role_name} --assume-role-policy-document file://snapRole.json
    if [[ $? != 0 ]]; then
      echo "!!!IAM role could not be created; exiting"
      rm snapPolicy.json
      rm snapRole.json
      exit 1
    fi

    #attach new policy to role:
    aws iam put-role-policy --role-name ${role_name} --policy-name ${policy_name} --policy-document file://snapPolicy.json
    if [[ $? != 0 ]]; then
      echo "!!!Role policy could not be attached; exiting"
      rm snapPolicy.json
      rm snapRole.json
      exit 1
    fi

    echo -e "\nSleeping 10 seconds: allowing IAM role to be populated to AWS"
    for ((i=0;i<11;i++)); do
      echo $((10-${i}))
      sleep 1
    done
  fi
  rm snapPolicy.json
  rm snapRole.json
}


create_lambda(){
  : '<create_lambda>
    - Function will create the Lambda job pertaining to the targeted EC2 hostname
    - If the named function already exists:
      - The EC2 hostname will be added as a target of the existing function
  <create_lambda>'
  role_arn=$(aws iam get-role --role-name ${role_name} | grep "Arn" | awk '{print $2}' | sed 's/,//' | sed 's/"//g')
  lambda_name="${component}-${environment}-snapshot-function"

  lambda_mk(){
    aws lambda create-function \
--function-name ${lambda_name} \
--runtime python2.7 \
--role ${role_arn} \
--description "Lambda function providing reoccurring EBS volume snapshots, as well as snapshot lifecycle management" \
--zip-file fileb://mastersnaps.zip \
--handler snap_handler.lambda_handler \
--environment Variables={Instance1="${hostname}"} \
--timeout 300 \
--memory-size 448
#--vpc-config SubnetIds=subnet-961e76f1,subnet-d2c5de8a,subnet-08d15341,SecurityGroupIds=sg-2595ed42 \
    if [[ $? == 0 ]];then
      echo -e "\nSuccessfully created Lambda"
    else
      echo "!!!Could not create Lambda function, exiting"
      exit 1
    fi
  }

  #if Lambda function exists, the EC2 hostname will be added as an environment variable
  aws lambda get-function --function-name ${lambda_name} > /dev/null 2>&1
  #[[ $? == 0 ]] && lambda_name+="_${epoch}"
  if [[ $? == 0 ]]; then
    function_config=$(aws lambda get-function-configuration --function-name ${lambda_name})
    variables=$(echo ${function_config} | sed 's/.*"Variables": { \(".*"\) } }.*/\1/')
    hostnames=$(echo ${variables} | sed -e 's/[",:]//g' -e 's/Instance[0-9]* //g')

    #read string into array, and iterate through tokens
    hostnames=($hostnames)
    counter=1
    envstring="Variables={"
    for inst in ${hostnames[@]};do
      envstring+="Instance${counter}="
      envstring+="${inst}"
      [[ ${counter} < ${#hostnames[@]} ]] && envstring+=","
      (( counter++ ))
    done
    envstring+=",Instance${counter}=${hostname}}"
    aws lambda update-function-configuration --function-name ${lambda_name} --environment "${envstring}"
    if [[ $? == 0 ]]; then
      echo "Successfully added hostname ${hostname} to function ${lambda_name}"
    else
      echo "!!Error!! Could not add target ${hostname} to ${lambda_name}"
      exit 1
    fi
  else
    #call the lambda_mk inner function to create the Lambda
    lambda_mk
  fi
}


create_cloudwatch(){
  : '<create_cloudwatch>
    - Function will create a scheduled Cloudwatch event
      from which the Lambda will be run on a reoccurrring
      schedule.
    - The frequency of Lambda trigger events, can be
      modified by giving an integer argument (representing
      hours between triggered events) to the function
    - If a Cloudwatch event exists sharing the same name,
      and has the same frequency argument, the function
      will be added to this event
      - If the frequency argument differs, a new Cloudwatch
        event will be created with the hourly argument added
        to the name as a means of differentiation
  <create_cloudwatch>'
  hourly=${1}
  frequency=$((${1}*60))
  rate_arg="rate(${frequency} minutes)"

  event_name="${component}-${environment}-snapshot-event"
  #If Cloudwatch event exists with given name, check it's frequency
  aws events describe-rule --name "${event_name}" > /dev/null 2>&1
  if [[ $? == 0 ]]; then
    #check the frequency of existing event, if same as arg: use the event
    echo -e "Discovered existing Cloudwatch event ${event_name}"
    event_data=$(aws events describe-rule --name "${event_name}")
    #echo ${event_data}
    event_rate=$(echo ${event_data} | sed 's/.*ScheduleExpression": "\(.*)\)".*/\1/')
    #echo ${event_rate}
    #if hourly rates are different, create a new event version
    if [[ "${rate_arg}" != "${event_rate}" ]]; then
      #create new Cloudwatch event name, with different hourly arg in title
      event_name="${event_name}-${hourly}hr"
      aws events put-rule --name ${event_name} --schedule-expression "${rate_arg}"
      if [[ $? == 0 ]]; then
        echo -e "\nSuccessfully created Cloudwatch event: ${event_name}"
      else
        echo -e "\n!!Unable to create Cloudwatch event: ${event_name}"
        exit 1
      fi
    else #use the existing Cloudwatch event
      echo -e "Utilizing ${event_name} to run ${lambda_name}"
    fi
  else
    #create the scheduled Cloudwatch event if it doesn't exist
    aws events put-rule --name ${event_name} --schedule-expression "${rate_arg}" \
    --description "Chronological execution of lambda function ${lambda_name}"

    if [[ $? == 0 ]]; then
      echo -e "\nSuccessfully created Cloudwatch event: ${event_name}"
    else
      echo -e "\n!!Unable to create Cloudwatch event: ${event_name}"
      exit 1
    fi
  fi
  #retrieve cloud arn info per event:
  cloud_arn=$(aws events describe-rule --name ${event_name} | grep "Arn" | awk '{print $2}' | sed 's/,//' | sed 's/"//g')

  #retrieve Lambda arn info:
  lambda_arn=$(aws lambda get-function --function-name ${lambda_name} | grep "FunctionArn" | awk '{print $2}' | sed 's/,//' | sed 's/"//g')

  #add Cloudwatch permissions to the Lambda function:
  aws lambda add-permission \
--function-name ${lambda_name} \
--statement-id ${event_name}-${epoch} \
--action 'lambda:InvokeFunction' \
--principal events.amazonaws.com \
--source-arn ${cloud_arn}

  if [[ $? == 0 ]]; then
    echo -e "\nSuccessfully added permission"
  else
    echo "!!!Permission could not be added; exiting"
    exit 1
  fi

  #add Lambda job as a target to the event
  aws events put-targets --rule ${component}-${environment}-snapshot-event --targets "Id"="1","Arn"="${lambda_arn}"

  if [[ $? == 0 ]]; then
    echo -e "\nSuccessfully added target"
  else
    echo "!!!Target could not be added; exiting"
    exit 1
  fi
}

invoke_lambda(){
  : '<invoke_lambda>
    - Invoke the newly created Lambda function locally
  <invoke_lambda>'
}

tare_down(){
  : '<tare_down>
    - Undo that which has been created
  <tare_down>'

  aws iam delete-role-policy --role-name plume-${environment}-snapshot-lambda-role --policy-name plume-${environment}-snapshot-lambda-policy
  aws iam delete-role --role-name plume-${environment}-snapshot-lambda-role
  aws lambda delete-function --function-name ${component}_${environment}-snapshot-function
  aws events remove-targets --rule ${component}-${environment}-snapshot-event --ids 1
  aws events delete-rule --name ${component}-${environment}-snapshot-event
  aws logs delete-log-group --log-group-name "/aws/lambda/${component}_${environment}-snapshot-function"
  exit
}

run_functions(){
  [[ "${delete}" == true ]] && tare_down
  [[ "${create_role}" == true ]] && create_IAM
  create_lambda
  create_cloudwatch ${frequency}
}
run_functions
