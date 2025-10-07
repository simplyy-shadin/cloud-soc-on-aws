import json
import boto3
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ec2 = boto3.client('ec2')
waf = boto3.client('wafv2')

def lambda_handler(event, context):
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Handle different event formats
        if 'body' in event:
            # API Gateway/Function URL format
            if isinstance(event['body'], str):
                alert_data = json.loads(event['body'])
            else:
                alert_data = event['body']
        else:
            # Direct Wazuh integration format
            alert_data = event
        
        # Extract attacker IP and rule ID
        attacker_ip = None
        rule_id = None
        
        if 'data' in alert_data:
            attacker_ip = alert_data['data'].get('srcip')
            rule_id = alert_data['data'].get('rule', {}).get('id')
        else:
            attacker_ip = alert_data.get('srcip')
            rule_id = alert_data.get('rule', {}).get('id')
        
        # Convert rule_id to string for comparison
        if rule_id is not None:
            rule_id = str(rule_id)
        
        logger.info(f"Extracted - IP: {attacker_ip}, Rule ID: {rule_id}")
        
        if not attacker_ip or not rule_id:
            logger.error("Could not extract IP or Rule ID from alert")
            logger.error(f"Available keys in alert: {list(alert_data.keys())}")
            return {
                'statusCode': 400,
                'body': json.dumps('Missing required fields: srcip or rule.id')
            }
        
        # Only process specific rule (placeholder for brute-force rule)
        TARGET_RULE_ID = "<YOUR_RULE_ID>"
        if rule_id == TARGET_RULE_ID:
            logger.info(f"Processing security alert from IP: {attacker_ip}")
            
            # Block the IP
            block_ip_in_security_group(attacker_ip)
            block_ip_in_waf(attacker_ip)
            
            return {
                'statusCode': 200,
                'body': json.dumps(f'Successfully blocked IP: {attacker_ip}')
            }
        else:
            logger.info(f"Rule ID {rule_id} is not a targeted rule")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Alert processed but no action taken for rule: {rule_id}')
        }
        
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        logger.error(f"Full event: {json.dumps(event)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def block_ip_in_security_group(ip_address):
    """Block IP by adding deny rule to security group"""
    try:
        # Replace with your security group ID
        SECURITY_GROUP_ID = "<YOUR_SECURITY_GROUP_ID>"
        
        response = ec2.authorize_security_group_ingress(
            GroupId=SECURITY_GROUP_ID,
            IpPermissions=[
                {
                    'IpProtocol': '-1',  # All protocols
                    'IpRanges': [
                        {
                            'CidrIp': f'{ip_address}/32',
                            'Description': 'Blocked by Wazuh - Automated response'
                        }
                    ]
                }
            ]
        )
        logger.info(f"Blocked IP {ip_address} in Security Group")
        
    except Exception as e:
        if "already exists" in str(e):
            logger.info(f"IP {ip_address} already blocked in Security Group")
        else:
            logger.error(f"Failed to block IP in Security Group: {str(e)}")

def block_ip_in_waf(ip_address):
    """Block IP using AWS WAF"""
    try:
        # WAF configuration placeholders
        IP_SET_NAME = "<YOUR_IP_SET_NAME>"
        IP_SET_ID = "<YOUR_IP_SET_ID>"
        SCOPE = "<REGIONAL_OR_GLOBAL>"
        
        current_ip_set = waf.get_ip_set(
            Scope=SCOPE,
            Id=IP_SET_ID,
            Name=IP_SET_NAME
        )
        
        current_addresses = current_ip_set['IPSet']['Addresses']
        new_ip = f'{ip_address}/32'
        
        if new_ip not in current_addresses:
            current_addresses.append(new_ip)
            
            response = waf.update_ip_set(
                Scope=SCOPE,
                Id=IP_SET_ID,
                Name=IP_SET_NAME,
                Addresses=current_addresses,
                LockToken=current_ip_set['LockToken']
            )
            logger.info(f"Successfully blocked IP {ip_address} in WAF")
        else:
            logger.info(f"IP {ip_address} already exists in WAF blocklist")
        
    except Exception as e:
        logger.error(f"Failed to block IP in WAF: {str(e)}")


