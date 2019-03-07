#!/bin/bash

#Url link for Lambda:
#-------------------
#https://s3-us-west-2.amazonaws.com/plume-global-lambda-deployment-packages/autoscale_lambda/Archive.zip

: ' Replication
  us-west-2 => ca-central-1
  eu-west-3 => eu-central-1
'

export AWS_PROFILE='plumeops'
export AWS_DEFAULT_REGION='us-west-2'
zip -g Archive.zip autoscale_clean.py
aws s3 cp Archive.zip s3://plume-ops-us-west-2-lambda-deployment-packages/autoscale_lambda/Archive.zip

export AWS_DEFAULT_REGION='eu-west-3'
aws s3 cp Archive.zip s3://plume-ops-eu-west-3-lambda-deployment-packages/autoscale_lambda/Archive.zip
