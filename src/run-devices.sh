#!/bin/bash

# sudo su
# cd /app/src
# ps -aux | grep python

# device-us-east-1 = ec2-34-207-193-122.compute-1.amazonaws.com = 172.31.87.123
# python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1 10 10

# device-us-west-2 = ec2-52-36-138-0.us-west-2.compute.amazonaws.com = 172.31.29.215
# python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2 10 10

# device-ap-northeast-1 = ec2-52-194-252-12.ap-northeast-1.compute.amazonaws.com = 172.31.36.63
# python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 10 10

# us-east-1
rm -f /var/log/gateway*.log
rm -f /var/log/device*.log
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-us-east-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-us-east-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-us-east-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-us-east-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-us-east-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-us-east-1 100 50 &
aws s3 rm s3://speedychain --recursive
aws s3 cp /var/log/gateway*.log s3://speedychain/log/
aws s3 cp /var/log/device*.log s3://speedychain/log/

# us-west-2
rm -f /var/log/gateway*.log
rm -f /var/log/device*.log
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-us-west-2 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-us-west-2 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-us-west-2 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-us-west-2 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-us-west-2 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-us-west-2 100 50 &
aws s3 rm s3://speedychain --recursive
aws s3 cp /var/log/gateway*.log s3://speedychain/log/
aws s3 cp /var/log/device*.log s3://speedychain/log/

# ap-northeast-1
rm -f /var/log/gateway*.log
rm -f /var/log/device*.log
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-ap-northeast-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-ap-northeast-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-ap-northeast-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-east-1      device-ap-northeast-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-us-west-2      device-ap-northeast-1 100 50 &
python2.7 Device.py 50.16.193.245 9090 gateway-ap-northeast-1 device-ap-northeast-1 100 50 &
aws s3 rm s3://speedychain --recursive
aws s3 cp /var/log/gateway*.log s3://speedychain/log/
aws s3 cp /var/log/device*.log s3://speedychain/log/