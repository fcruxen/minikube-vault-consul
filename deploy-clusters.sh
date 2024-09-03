#!/bin/bash
export DC_ONE_NAME="north"
export DC_TWO_NAME="south"
export CONSUL_DOMAIN="fcruxen"
export CIDR_ONE="10.100.0.0"
export CIDR_TWO="10.200.0.0"
export ONE_CLUSTER_IP
export TWO_CLUSTER_IP
export INTERNAL_ONE_IP
export INTERNAL_TWO_IP
export CONSUL_HTTP_ADDR
export CONSUL_HTTP_TOKEN
export VAULT_SERVER_PORT
export VAULT_TOKEN
export VAULT_ADDR
export CURRENT_NAME



create_clusters () {
    minikube start -p ${DC_TWO_NAME} --driver=kvm --cpus 4 --memory 8192 --cni=calico
    minikube start -p ${DC_ONE_NAME} --driver=kvm --cpus 4 --memory 8192 --cni=calico
    ONE_CLUSTER_IP=$(minikube ip -p ${DC_ONE_NAME})
    TWO_CLUSTER_IP=$(minikube ip -p ${DC_TWO_NAME})
    while [[ "$CALICO_STATE" != "Running" ]]; do
        sleep 10
        CALICO_STATE=$(kubectl get pods -n kube-system | grep calico-kube-controllers | awk '{print $3}')
        echo "CALICO is ${CALICO_STATE}"
    done
    cat templates/ippool.yml | sed 's/_CIDR_/'${CIDR_ONE}'/' > artifacts/ippool-${DC_ONE_NAME}.yml
    cat templates/ippool.yml | sed 's/_CIDR_/'${CIDR_TWO}'/' > artifacts/ippool-${DC_TWO_NAME}.yml
    kubectl replace -f artifacts/ippool-${DC_ONE_NAME}.yml --context ${DC_ONE_NAME}
    kubectl replace -f artifacts/ippool-${DC_TWO_NAME}.yml --context ${DC_TWO_NAME}
    minikube stop -p ${DC_ONE_NAME}
    minikube start -p ${DC_ONE_NAME}
    minikube stop -p ${DC_TWO_NAME}
    minikube start -p ${DC_TWO_NAME}
}

change_context () {
    kubectl config use-context ${CURRENT_NAME}    
}

check_vault_status () {
  echo "Checking Vault State..."
  VAULT_STATE="Starting"
  while [[ "$VAULT_STATE" != "Running" ]]; do
      VAULT_STATE=$(kubectl get pods -n vault | grep vault-0 | awk '{print $3}')
      echo "Vault is ${VAULT_STATE}"
      sleep 10
  done
}

install_vault_primary () {
    cat templates/vault-one.yml | sed 's/_DC_ONE_NAME_/'${DC_ONE_NAME}'/' > artifacts/vault-${DC_ONE_NAME}.yml
    helm install vault hashicorp/vault -n vault --create-namespace --values artifacts/vault-${DC_ONE_NAME}.yml
    check_vault_status
    kubectl exec -it vault-0 -n vault -- vault operator init > artifacts/vault-tokens.txt
    sed -e 's/\x1b\[[0-9;]*m//g' -i artifacts/vault-tokens.txt
}

install_vault_secondary () {
    cat templates/vault-two.yml | sed 's/_DC_TWO_NAME_/'${DC_TWO_NAME}'/' > artifacts/vault-${DC_TWO_NAME}.yml
    sed -i 's/_ONE_CLUSTER_IP_/'${ONE_CLUSTER_IP}'/' artifacts/vault-${DC_TWO_NAME}.yml

    helm install vault hashicorp/vault -n vault --create-namespace --values artifacts/vault-${DC_TWO_NAME}.yml
    echo "Checking Vault State..."
    check_vault_status
    sleep 10
}

unseal_vault () {
    KEY_1=$(cat artifacts/vault-tokens.txt | grep "Key 1" | awk '{print $4}')
    KEY_2=$(cat artifacts/vault-tokens.txt | grep "Key 2" | awk '{print $4}')
    KEY_3=$(cat artifacts/vault-tokens.txt | grep "Key 3" | awk '{print $4}')

    kubectl exec -it vault-0 -n vault -- vault operator unseal ${KEY_1}
    kubectl exec -it vault-0 -n vault -- vault operator unseal ${KEY_2}
    kubectl exec -it vault-0 -n vault -- vault operator unseal ${KEY_3}
}

create_vault_auth () {
    vault write auth/${CURRENT_NAME}/role/consul-server \
            bound_service_account_names=consul-server \
            bound_service_account_namespaces="consul" \
            policies="gossip,connect-ca-${CURRENT_NAME},consul-cert-${CURRENT_NAME}" \
            ttl=24h

    vault write auth/${CURRENT_NAME}/role/consul-client \
            bound_service_account_names=consul-client \
            bound_service_account_namespaces="consul" \
            policies="gossip" \
            ttl=24h

    vault write auth/${CURRENT_NAME}/role/consul-server-acl-init \
            bound_service_account_names=consul-server-acl-init \
            bound_service_account_namespaces="consul" \
            policies="replication-token" \
            ttl=24h

    vault write auth/${CURRENT_NAME}/role/consul-ca \
            bound_service_account_names="*" \
            bound_service_account_namespaces="consul" \
            policies=ca-policy \
            ttl=1h

    vault write pki/roles/consul-cert-${CURRENT_NAME} \
    allowed_domains="${CURRENT_NAME}.${CONSUL_DOMAIN},server.${CURRENT_NAME}.${CONSUL_DOMAIN},consul-server,consul-server.consul,consul-server.consul.svc" \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_localhost=true \
    generate_lease=true \
    max_ttl="24h"

    vault policy write connect-ca-${CURRENT_NAME} - <<-EOF
      path "/sys/mounts" {
        capabilities = [ "read" ]
      }
      path "/sys/mounts/connect_root" {
        capabilities = [ "create", "read", "update", "delete", "list" ]
      }
      path "/sys/mounts/${CURRENT_NAME}/connect_inter" {
        capabilities = [ "create", "read", "update", "delete", "list" ]
      }
      path "/connect_root/*" {
        capabilities = [ "create", "read", "update", "delete", "list" ]
      }
      path "/${CURRENT_NAME}/connect_inter/*" {
        capabilities = [ "create", "read", "update", "delete", "list" ]
      }
EOF

    vault policy write consul-cert-${CURRENT_NAME} - <<-EOF
      path "pki/issue/consul-cert-${CURRENT_NAME}"
      {
        capabilities = ["create","update"]
      }
EOF
}

configure_vault_primary () {
    VAULT_SERVER_PORT=$(kubectl get svc/vault -n vault -o yaml | yq '.spec.ports[0].nodePort')
    VAULT_TOKEN=$(cat artifacts/vault-tokens.txt | grep Root | awk '{print $4}' | strings)
    VAULT_ADDR=http://${ONE_CLUSTER_IP}:${VAULT_SERVER_PORT}
    vault secrets enable -path=consul kv-v2

    vault policy write gossip - <<EOF
      path "consul/data/secret/gossip" {
        capabilities = ["read"]
      }
      path "consul/data/secret/bootstrap-token" {
        capabilities = ["read"]
      }
      path "consul/data/secret/replication" {
        capabilities = ["read"]
      }
EOF

    vault kv put consul/secret/replication token="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    vault kv put consul/secret/bootstrap-token token="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    vault kv put consul/secret/gossip key="$(consul keygen)"

    vault policy write replication-token - <<EOF
      path "consul/data/secret/replication" {
        capabilities = ["read"]
      }
      path "consul/data/secret/bootstrap-token" {
        capabilities = ["read"]
      }
EOF

    vault secrets enable pki
    vault write pki/root/generate/internal common_name="Consul CA" ttl=87600h

    vault policy write ca-policy - <<EOF
      path "pki/cert/ca" {
      capabilities = ["read"]
      }
EOF
    vault auth enable -path=${DC_ONE_NAME} kubernetes
    vault auth enable -path=${DC_TWO_NAME} kubernetes
    vault write auth/${DC_ONE_NAME}/config kubernetes_host=https://kubernetes.default.svc
    CURRENT_NAME=${DC_ONE_NAME}
    create_vault_auth
}

configure_vault_secondary () {    
    
    K8S_CA_CERT="$(kubectl get secret consul-auth-method -n consul --context ${DC_TWO_NAME} -o jsonpath='{.data.ca\.crt}' | base64 -d)"
    
    K8S_JWT_TOKEN="$(kubectl get secret consul-auth-method -n consul --context ${DC_TWO_NAME} -o jsonpath='{.data.token}' | base64 -d)"
    
    vault write auth/${DC_TWO_NAME}/config \
        kubernetes_host=https://${TWO_CLUSTER_IP}:8443 \
        disable_local_ca_jwt=true \
        token_reviewer_jwt="${K8S_JWT_TOKEN}" \
        kubernetes_ca_cert="${K8S_CA_CERT}"
    CURRENT_NAME=${DC_TWO_NAME}
    create_vault_auth
    sleep 10
}

install_consul_primary () {
    cat templates/consul-one.yml | sed 's/_DC_ONE_NAME_/'${DC_ONE_NAME}'/' > artifacts/consul-${DC_ONE_NAME}.yml
    sed -i 's/_CONSUL_DOMAIN_/'${CONSUL_DOMAIN}'/' artifacts/consul-${DC_ONE_NAME}.yml
    helm install consul hashicorp/consul -n consul --create-namespace --values artifacts/consul-${DC_ONE_NAME}.yml --wait
}

route_nodes () {
    INTERNAL_ONE_IP=$(minikube ssh -p ${DC_ONE_NAME} 'ifconfig -a' | grep -b3 eth1 | grep inet | awk '{print $3}' | tr -d 'addr:' | tr -d "\n")
    INTERNAL_TWO_IP=$(minikube ssh -p ${DC_TWO_NAME} 'ifconfig -a' | grep -b3 eth1 | grep inet | awk '{print $3}' | tr -d 'addr:' | tr -d "\n")
    minikube ssh -p ${DC_ONE_NAME} "sudo ip route add ${TWO_CLUSTER_IP}/32 via ${INTERNAL_TWO_IP}"
    minikube ssh -p ${DC_TWO_NAME} "sudo ip route add ${ONE_CLUSTER_IP}/32 via ${INTERNAL_ONE_IP}"
}

install_consul_secondary () {
    route_nodes

    cat templates/consul-two.yml | sed 's/_DC_ONE_NAME_/'${DC_ONE_NAME}'/' > artifacts/consul-${DC_TWO_NAME}.yml
    sed -i 's/_CONSUL_DOMAIN_/'${CONSUL_DOMAIN}'/' artifacts/consul-${DC_TWO_NAME}.yml
    sed -i 's/_DC_TWO_NAME_/'${DC_TWO_NAME}'/' artifacts/consul-${DC_TWO_NAME}.yml
    sed -i 's/_ONE_CLUSTER_IP_/'${ONE_CLUSTER_IP}'/' artifacts/consul-${DC_TWO_NAME}.yml
    sed -i 's/_TWO_CLUSTER_IP_/'${TWO_CLUSTER_IP}'/' artifacts/consul-${DC_TWO_NAME}.yml
    
    helm install consul hashicorp/consul -n consul --create-namespace --values artifacts/consul-${DC_TWO_NAME}.yml &
    
    sleep 3
    configure_vault_secondary
    
    sleep 3
    INJECTOR_POD=$(kubectl get pod -n consul | grep injector | awk '{print $1}')
    SERVER_POD=$(kubectl get pod -n consul | grep server-0 | awk '{print $1}')
    MESH_POD=$(kubectl get pod -n consul | grep mesh-gateway | awk '{print $1}')
    kubectl delete pod/${INJECTOR_POD} -n consul
    kubectl delete pod/${SERVER_POD} -n consul
    kubectl delete pod/${MESH_POD} -n consul

    echo "Checking CONSUL State..."
    while [[ "$CONSUL_STATE" != "Running" ]]; do
        CONSUL_STATE=$(kubectl get pods -n consul | grep consul-server-0 | awk '{print $3}')
        echo "CONSUL is ${CONSUL_STATE}"
        sleep 10
    done
}

transparent_proxy () {
  CONSUL_HTTP_TOKEN=$(vault kv get /consul/secret/bootstrap-token | grep token | awk '{print $2}' | strings)
  CONSUL_HTTP_ADDR=${ONE_CLUSTER_IP}:32256
  consul config write templates/proxy.hcl  
}

install_test_services () {
  cat templates/static-server.yml | sed 's/_DC_NAME_/'${CURRENT_NAME}'/' > artifacts/static-server-${CURRENT_NAME}.yml
  kubectl create -f artifacts/static-server-${CURRENT_NAME}.yml
  kubectl create -f templates/static-client.yml

}

helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

create_clusters

export CURRENT_NAME=${DC_ONE_NAME}

change_context

install_vault_primary

unseal_vault

configure_vault_primary

install_consul_primary

echo "Config finished on ${DC_ONE_NAME} cluster"

CURRENT_NAME=${DC_TWO_NAME}

change_context

install_vault_secondary

install_consul_secondary

echo "Config finished on ${DC_TWO_NAME} cluster"

echo "Enabling transparent proxy"
transparent_proxy

CURRENT_NAME=${DC_ONE_NAME}
change_context

echo "Add Allow All Intention"
kubectl create -f templates/intentions.yml

echo "Installing Test Services in ${DC_ONE_NAME}"
install_test_services

CURRENT_NAME=${DC_TWO_NAME}
change_context

echo "Installing Test Services in ${DC_TWO_NAME}"
install_test_services

echo "Access Consul at http://${ONE_CLUSTER_IP}:32256"
echo "Access VAULT at http://${ONE_CLUSTER_IP}:31888"