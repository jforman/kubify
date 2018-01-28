#!/bin/bash

# Script to use etcd to return a list of node IPs with pod subnets on each host.
# Example output: Node1IP:Node1PodSubnetCidr,Node2IP:Node2PodSubnetCidr,...

CA_DIR=/etc/ssl/certs/
APISERVER_DIR=/etc/ssl/certs/
CA_FILE=ca.pem
CERT_FILE=kubernetes.pem
KEY_FILE=kubernetes-key.pem
ETCD_ENDPOINT=$1
ETCD_SUBNETS_DIR=/coreos.com/network/subnets

run_etcd() {
#    echo $( /usr/bin/etcdctl --ca-file $CA_DIR$CA_FILE --cert-file $APISERVER_DIR$CERT_FILE --key-file $APISERVER_DIR$KEY_FILE --endpoints $ETCD_ENDPOINT ${@:1} )
    echo $( /usr/bin/etcdctl ${@:1} )

}

get_pod_subnet_paths() {
    echo $( run_etcd ls \--recursive $ETCD_SUBNETS_DIR )
}

get_etcd_value() {
    echo $( run_etcd get $1 )
}

get_public_ip() {
    echo $1 | awk -F'"' '{print $4}'
}

get_raw_cidr() {
    echo $( echo $1 | awk -F"/" '{ print $NF }' )
}

get_ip_cidr() {
    RAW_SUBNET=$( get_raw_cidr $1 )
    echo $( echo $RAW_SUBNET | sed -e 's/-/\//g' )

}

run_main() {
    TOTAL=
    for cur_subnet_path in $( get_pod_subnet_paths );
    do
        ETCD_POD_SUBNET_DICT=$( get_etcd_value $cur_subnet_path )
        PUBLIC_IP=$( get_public_ip $ETCD_POD_SUBNET_DICT )
        CIDR=$( get_ip_cidr $cur_subnet_path )
        #echo "$cur_subnet_path ----> $ETCD_POD_SUBNET_DICT -----> $PUBLIC_IP"
        #echo "$CIDR ----> $PUBLIC_IP"
        TOTAL="$PUBLIC_IP:$CIDR,$TOTAL"
    done
    # Remove the trailing comma
    echo -n $TOTAL | head -c-1
}

run_main
