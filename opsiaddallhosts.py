#!/usr/bin/env python
#oci cli commpartment to get all compartment names into a file.This needs to be done before running the script
#oci iam compartment list --compartment-id-in-subtree true --access-level "ACCESSIBLE"|jq -r '.data[].name' > complist.txt
#To exclude certain compartment from enabling OPSI remove it from the file or only add few compartment names to do in batch
import time
import oci

#To use in Cloud shell
delegation_token = open('/etc/oci/delegation_token', 'r').read()
signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
     delegation_token=delegation_token)

#For local use
#config = oci.config.from_file("~/.oci/config")

COMPARTMENT_ID=input("Enter the tenancy ocid: ")

#To use in cloudshell
identity_client = oci.identity.IdentityClient(config={},signer=signer)
opsi_client = oci.opsi.OperationsInsightsClient(config={},signer=signer)
compute_client =  oci.core.ComputeClient(config={},signer=signer)
compute_instance_agent_client = oci.compute_instance_agent.PluginClient(config={},signer=signer)
management_agent_client = oci.management_agent.ManagementAgentClient(config={},signer=signer)

#To use in local environment
#identity_client = oci.identity.IdentityClient(config)
#opsi_client = oci.opsi.OperationsInsightsClient(config)
#compute_client =  oci.core.ComputeClient(config)
#compute_instance_agent_client = oci.compute_instance_agent.PluginClient(config)
#management_agent_client = oci.management_agent.ManagementAgentClient(config)

#list all compartments in a tenant
list_compartments_response = identity_client.list_compartments(
    compartment_id=COMPARTMENT_ID,
    compartment_id_in_subtree=True)

comp_list_file = input("Enter the absolute file path containing compartment list: ")
with open(comp_list_file,"r") as f:
    comp_list_opsi = f.read().split()

for comp in list_compartments_response.data:
    if comp.name in comp_list_opsi:
        try:
            print(f'Compartment name is {comp.name}')

            list_instances_response = compute_client.list_instances(compartment_id=comp.id)
           
            list_host_insights_response = opsi_client.list_host_insights(compartment_id=comp.id,status=["DISABLED", "ENABLED"],lifecycle_state=["ACTIVE","CREATING","FAILED","NEEDS_ATTENTION"])
            hostinsight = list_host_insights_response.data.items

            list_host_insights_failed = opsi_client.list_host_insights(compartment_id=comp.id,status=["ENABLED"],lifecycle_state=["FAILED"])
            hostinsight_enable_failed = list_host_insights_failed.data.items

            for instance in list_instances_response.data:
                try:
                    get_image_response = compute_client.get_image(image_id=instance.image_id)
                    os = get_image_response.data.operating_system

                    if os == "Oracle Linux" and instance.lifecycle_state == "RUNNING":
                        hostinsight_list = [host for host in hostinsight if (instance.display_name in host.host_display_name)]
                        
                        get_instance_agent_plugin_response = compute_instance_agent_client.get_instance_agent_plugin(
                        instanceagent_id=instance.id,
                        compartment_id=comp.id,
                        plugin_name="Management Agent")
                        pluginstatus = get_instance_agent_plugin_response.data.status
                        if (pluginstatus in ("STOPPED","RUNNING") or pluginstatus != "INVALID") and len(hostinsight_list) == 0:
                            create_host_insight_response = opsi_client.create_host_insight(
                            create_host_insight_details=oci.opsi.models.CreateMacsManagedCloudHostInsightDetails(
                            entity_source="MACS_MANAGED_CLOUD_HOST",
                            compartment_id=comp.id,
                            compute_id=instance.id))
    
                            print(",".join([str(comp.name),str(instance.display_name),"OPSI Enabled"]))
                            
                        if len(hostinsight_enable_failed) > 0 and (pluginstatus in ("STOPPED","RUNNING") or pluginstatus != "INVALID"):
                            hostinsight_failed_list = [host for host in hostinsight_enable_failed if (instance.display_name in host.host_display_name)]
                            for hostfailed in hostinsight_failed_list:
                                enable_host_insight_response = opsi_client.enable_host_insight(
                                enable_host_insight_details=oci.opsi.models.EnableMacsManagedCloudHostInsightDetails(
                                entity_source="MACS_MANAGED_CLOUD_HOST"),
                                host_insight_id=hostfailed.id)
                except Exception as ex:
                    print(ex)
        except Exception as ex1:
            print(ex1)
