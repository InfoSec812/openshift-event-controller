"""
A plugin for the event listen which upon creation of a new route, it triggers the creation of a letsencrypt certificate and key. 
"""

import requests


def handle_event(watcher, event, config):
    """
    Handles an event from OCP

    Args:
        watcher (dict): The watcher object which monitors for changes to the OpenShift cluster
        event (dict): The event object describing what has changed
        config (dict): The configuration of this event handler
    
    Returns:
        void
    """
    message = "Kind: {0}; Name: {1}; Event Type:{2}".format(event['object']['kind'], event['object']['metadata']['name'], event['type'])
    log_level = config.get('message_log_level','INFO')

    if isinstance(event, dict) and 'type' in event:
        if event['type'] == 'ADDED':
            route_name = event['object']['metadata']['name']
            k8s_endpoint = watcher.config.k8s_endpoint
            k8s_namespace = watcher.config.k8s_namespace
            k8s_token = watcher.config.k8s_token
            k8s_ca = watcher.config.k8s_ca

            route_details = get_route_details(k8s_endpoint, k8s_namespace, route_name, k8s_token, k8s_ca)

            hostname = route_details.spec.host

            router_pod_name = get_router_pod(k8s_endpoint, k8s_token, k8s_ca)

    return message, log_level

def load_certificate_results(k8s_endpoint, k8s_namespace, k8s_token, k8s_ca, route_name, host_cert, host_key):
    """
    Given a certificate and key, reconfigure the route to use that certificate/key pair

    Args:
        k8s_endpoint (string): The hostname of the OpenShift cluster
        k8s_namespace (string): The namespace in which the route
        k8s_token (string): The token to be used to authenticate to the OpenShift cluster
        k8s_ca (string): The CA certificate used to validate connections to the OpenShift cluster
        route_name (string): Name of the route object
        host_cert (string): The X.509 Certificate for the host
        host_key (string): The RSA key for the host certificate
    Returns:
        bool: True if the operation succeeds
    """
    return None

def exec_certbot_registration(k8s_endpoint, k8s_token, k8s_ca, router_pod_name, hostname):
    """
    Given connection details for the OpenShift cluster, execute certbot on the specified router pod in order
    to create a certificate for the specified route hostname

    Args:
        k8s_endpoint (string): The hostname of the OpenShift cluster
        k8s_namespace (string): The namespace in which the route
        k8s_token (string): The token to be used to authenticate to the OpenShift cluster
        k8s_ca (string): The CA certificate used to validate connections to the OpenShift cluster
    Returns:
        bool: True if the operation succeeds
    """
    return None

def get_router_pod(k8s_endpoint, k8s_token, k8s_ca):
    """
    Given a endpoint, and credentials; retrieve the router pod's name

    Args:
        k8s_endpoint (string): The hostname of the OpenShift cluster
        k8s_token (string): The token to be used to authenticate to the OpenShift cluster
        k8s_ca (string): The CA certificate used to validate connections to the OpenShift cluster
    Returns:
        string: Name of the router pod
    """
    payload = {'labelSelector': 'letsencrypt=true'}
    pod_info_req = requests.get(
                'https://{0}/api/v1/namespaces/default/pods'.format(k8s_endpoint),
                params=payload,
                headers={
                    'Authorization': 'Bearer {0}'.format(k8s_token),
                    'Content-Type':'application/strategic-merge-patch+json'
                },
                verify=k8s_ca)
    if pod_info_req.status_code is 200:
        return pod_info_req.json[0].metadata.name
    else:
        return None

def get_route_details(k8s_endpoint, k8s_namespace, k8s_token, k8s_ca, route_name):
    """
    Given the route name, endpoint, and credentials; retrieve the route details

    Args:
        k8s_endpoint (string): The hostname of the OpenShift cluster
        k8s_namespace (string): The namespace in which the route
        k8s_token (string): The token to be used to authenticate to the OpenShift cluster
        k8s_ca (string): The CA certificate used to validate connections to the OpenShift cluster
        route_name (string): The name of the route object

    Returns:
        dict: The details about the route
    """
    req = requests.get(
                'https://{0}/oapi/v1/namespaces/{1}/routes/{2}'
                .format(k8s_endpoint, k8s_namespace, route_name),
            headers={
                'Authorization': 'Bearer {0}'.format(k8s_token),
                'Content-Type':'application/strategic-merge-patch+json'
            },
            verify=k8s_ca)

    return req.json
