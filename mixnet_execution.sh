#!/bin/bash
if [ -z ${NUM_CONSORTIUMPEERS+x} ]; then NUM_CONSORTIUMPEERS=4; fi
if [ -z ${NUM_MIXPEERS+x} ]; then NUM_MIXPEERS=4; fi
if [ -z ${NUM_INPUTS+x} ]; then NUM_INPUTS=4; fi
if [ -z ${NUM_MALICIOUS_DKG+x} ]; then NUM_MALICIOUS_DKG=0; fi
if [ -z ${NUM_MALICIOUS_THRES+x} ]; then NUM_MALICIOUS_THRES=0; fi
if [ -z ${SINGLE_RECOVERY+x} ]; then SINGLE_RECOVERY=""; else SINGLE_RECOVERY="-sr"; fi

# remove old consortium data
rm consortium/*

# DKG for consortium is only performed if SKIP_CONSORTIUM_DKG is NOT set
if [ -z ${SKIP_CONSORTIUM_DKG+x} ]; then
  python run.py --logprefix consortium --numpeers $NUM_CONSORTIUMPEERS -mdkg $NUM_MALICIOUS_DKG -mthres $NUM_MALICIOUS_THRES $SINGLE_RECOVERY start-clean
  python mixnet_cli.py consortium-keygen
  python run.py stop
fi

python run.py --numpeers $NUM_MIXPEERS -mdkg $NUM_MALICIOUS_DKG -mthres $NUM_MALICIOUS_THRES $SINGLE_RECOVERY start-clean
python mixnet_cli.py keygen

for ((i = 0; i < $NUM_INPUTS; i++)); do
  python mixnet_cli.py register --input $i
done

python mixnet_cli.py commit
python mixnet_cli.py perform
python mixnet_cli.py decrypt
python run.py stop

python run.py --logprefix consortium --numpeers $NUM_CONSORTIUMPEERS -mdkg $NUM_MALICIOUS_DKG -mthres $NUM_MALICIOUS_THRES $SINGLE_RECOVERY start
python mixnet_cli.py --numpeers $NUM_MIXPEERS recover
python run.py stop
