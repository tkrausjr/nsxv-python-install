'''
#!/usr/bin/env python
'''

import base64
import urllib2
import httplib
import time
import xml.etree.ElementTree as ET

# Define variables needed for NSX Manager Deployment / Configuration
# Most of these will be used by ansible/ovftool command to deploy NSX Manager OVA
# Then the rest of NSXv install just needs (nsxMgrIp,nsxMgrUsername,nsxMgrPassword,configureSSO)
nsxMgrHostName='python-smt-nsxmgr'
nsxMgrNetwork='Internal-vLan-10'
nsxMgrIp='192.168.10.220'
nsxMgrPort=443
nsxMgrMask='255.255.255.0'
nsxMgrGw='192.168.10.1'
nsxMgrDns1='192.168.20.50'
nsxMgrNtpSvr='pool.ntp.org'
nsxMgmtDatastore='NFS_FAS2240'
nsxMgmtCluster='SuperMicro Cluster'
nsxMgmtDatacenter='Production'
mgmtVcIp='192.168.10.10'
mgmtVcUser='tkraus'
mgmtVcPassword='NSXv123!'
configureSSO=True
nsxMgrUsername = "admin"
nsxMgrPassword = "VMware1!VMware1!"
creds= base64.urlsafe_b64encode(nsxMgrUsername + ':' + nsxMgrPassword)
headers = {'Content-Type' : 'application/xml','Authorization' : 'Basic ' + creds }

# Define variables needed for NSX Controller Deployment / Configuration
nsxControllerQty=2
ctlDatastoreId='datastore-849'
ctlClusterId='domain-c863'
ctlNetworkId='dvportgroup-30'
mgtIpRangeStart='192.168.10.216'
mgtIpRangeStop='192.168.10.219'
mgtIpRangeMaskLength='24'
mgtIpRangeDns1='192.168.20.50'
mgtIpRangeDns1=''
mgtIpRangeGw='192.168.10.1'
jobpollingInterval=35

# Define variables needed for VXLAN Cluster Preparation and Configuration
computeCluster='domain-c863'
computeVcIp='labvcenter.hoodlumnet.com'
computeVcUser='tkraus@hoodlumnet.com'
computeVcPass='NSXv123!'
vxlanDvsId='dvs-25'
vxlanVtepVlanId='0'
vxlanVtepTeaming='FAILOVER_ORDER'
computeIpRangeStart='192.168.35.40'
computeIpRangeStop='192.168.35.50'
computeIpRangeMaskLength='24'
computeIpRangeGw='192.168.35.1'
computeIpRangeDns1='192.168.20.50'
tzName = 'VIO-TZ1'
vxlanReplicationMode='UNICAST_MODE'
vxlanMtu='1500'

def resgister_nsxmgr(vcIp,vcUser,vcPass):
    xml_string ='<vcInfo><ipAddress>'+vcIp+'</ipAddress><userName>'+vcUser+'</userName><password>'+vcPass+'</password><assignRoleToUser>true</assignRoleToUser></vcInfo>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('PUT', 'https://' + nsxMgrIp + '/api/2.0/services/vcconfig',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     " + str(response.status) + "=Error, NSX Manager not registered successfully "
            print str(responseData)
            exit(1)
    else:
            print "     NSX Manager ("+nsxMgrIp+")" ","+" registered to " + vcIp+" successfully."
            return 
        
#(Optional function) if selected - Configure SSO
def configure_sso(ssoVcIp,ssoAdminUser,ssoAdminPass):
    xml_string ='<ssoConfig><ssoLookupServiceUrl>https://'+ ssoVcIp +':7444/lookupservice/sdk</ssoLookupServiceUrl><ssoAdminUsername>'+ ssoAdminUser +'</ssoAdminUsername><ssoAdminUserpassword>'+ ssoAdminPass +'</ssoAdminUserpassword></ssoConfig>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/services/ssoconfig',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     "+str(response.status) + "=Error, SSO NOT configured successfully "
            print "     "+str(responseData)
            exit(1)
    else:
            print "     SSO configured successfully"
            return 
        
# Add an IP Pool to NSX Manager
def add_ippool (ipRangeName,ipRangeMaskLength,ipRangeGw,ipRangeDns1,ipRangeDns2,ipRangeStart,ipRangeStop):
    xml_string ='<ipamAddressPool><name>'+ipRangeName+'</name><prefixLength>'+ipRangeMaskLength+'</prefixLength><gateway>'+ipRangeGw+'</gateway><dnsServer1>'+ipRangeDns1+'</dnsServer1><dnsServer2>'+ipRangeDns2+'</dnsServer2><ipRanges><ipRangeDto><startAddress>'+ipRangeStart+'</startAddress><endAddress>'+ipRangeStop+'</endAddress></ipRangeDto></ipRanges></ipamAddressPool>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/services/ipam/pools/scope/globalroot-0',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 201:
            print "     "+str(response.status) + "=Error, IP Pool NOT created successfully "
            print "     "+str(responseData)
            exit(1)
    else:
            print "IP Pool "+ str(responseData)+" created successfully"
            return str(responseData)

# Add an NSX controller
def add_controller (controllerName,ipPoolId,resourcePoolId,datastoreId,networkId,controllerPass):
    xml_string ='<controllerSpec><name>'+controllerName+'</name><description>'+controllerName+'</description><ipPoolId>'+ipPoolId+'</ipPoolId><resourcePoolId>'+resourcePoolId+'</resourcePoolId><datastoreId>'+datastoreId+'</datastoreId><deployType>small</deployType><networkId>'+networkId+'</networkId><password>'+controllerPass+'</password></controllerSpec>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/vdn/controller',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 201:
            print "     "+str(response.status) + "=Error, Controller creation NOT started..."
            print "     "+str(responseData)
            exit(1)
    else:
            print "     NSX Controller deployment "+str(responseData)+" started ..."
            return str(responseData)

# Query NSX controller deployment
def query_controllerDeploy (ctlDeployJobId):  
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('GET', 'https://' + nsxMgrIp + '/api/2.0/vdn/controller/progress/' + ctlDeployJobId,None,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     "+str(response.status) + "=Error, Controller Deployment status query not successful"
            exit(1)
    else:
            print "     NSX Controller Deployment status query successful"
            rootXml=ET.fromstring(str(responseData))
            jobStatus = rootXml.find('status').text
            return jobStatus

# Prepare Compute Cluster for NSX - Install VIBs
def prepare_cluster(nsxClusterId):
    xml_string ='<nwFabricFeatureConfig><resourceConfig><resourceId>'+nsxClusterId+'</resourceId></resourceConfig></nwFabricFeatureConfig>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/nwfabric/configure',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     "+str(response.status) + "=Error, Cluster Preparation FAILED ! ..."
            print "     "+str(responseData)
            exit(1)
    else:
            print "     Successfully began cluster preparation with Job ID " + str(responseData)
            return str(responseData)

# Query a NSX Manager Job or Task with ID
def query_nsxjob(nsxJobId):  
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('GET', 'https://' + nsxMgrIp + '/api/2.0/services/taskservice/job/' + nsxJobId ,None,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     "+str(response.status) + "=Error, NSX Job status query not successful"
            exit(1)
    else:
            print "     NSX Jobstatus query successful"
            rootXml=ET.fromstring(str(responseData))
            print '     rootXml = '+ str(rootXml)
            nsxjobStatus = rootXml.find(".//status").text
            return nsxjobStatus

# Configure VXLAN vTEPs
def configure_cluster(vxlanClusterId,vxlanDvsId,vxlanVtepVlanId,vxlanVtepTeaming,vxlanIpPoolId,vxlanVtepMtu):
    if vxlanVtepTeaming =='FAILOVER_ORDER' or vxlanVtepTeaming=='ETHER_CHANNEL' or vxlanVtepTeaming=='LACP_ACTIVE' or vxlanVtepTeaming=='LACP_PASSIVE' or vxlanVtepTeaming=='LACP_V2':
        vxlanVmkQty = '1'
    else:
        vxlanVmkQty = '2'
	
    xml_string ='<nwFabricFeatureConfig><featureId>com.vmware.vshield.vsm.vxlan</featureId><resourceConfig><resourceId>'+vxlanClusterId+'</resourceId><configSpec class="clusterMappingSpec"><switch><objectId>'+vxlanDvsId+'</objectId></switch><vlanId>'+vxlanVtepVlanId+'</vlanId><vmknicCount>'+vxlanVmkQty+'</vmknicCount><ipPoolId>'+vxlanIpPoolId+'</ipPoolId></configSpec></resourceConfig><resourceConfig><resourceId>'+vxlanDvsId+'</resourceId><configSpec class="vdsContext"><switch><objectId>'+vxlanDvsId+'</objectId></switch><mtu>'+vxlanVtepMtu+'</mtu><teaming>'+vxlanVtepTeaming+'</teaming></configSpec></resourceConfig></nwFabricFeatureConfig>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/nwfabric/configure',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 200:
            print "     "+str(response.status) +", Error - VXLAN NOT configured on " + vxlanClusterId
            print "     "+str(responseData)
            exit(1)
    else:
            print "     VXLAN succesfully configured on " + vxlanClusterId
            return str(responseData)
        
# Create Segment ID Range
def create_segmentrange(segmentBegin, segmentEnd):
    xml_string ='<segmentRange><name>'+segmentBegin+'-'+segmentEnd+'</name><begin>'+segmentBegin+'</begin><end>'+segmentEnd+'</end></segmentRange>'   
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/vdn/config/segments',xml_string,headers)
    response = conn.getresponse()
    responseData = response.read()
    if response.status != 201:
            print "     "+str(response.status) + "=Error, Segment ID NOT added successfully..."
            print "     "+str(responseData)
            exit(1)
    else:
            print "     Success, Segment ID added successfully  ..."
            return str(responseData)
        
# Create the Transport Zone Function 
def create_tz(tz_name, tz_cluster,tzcontrolPlaneMode):
    xml_string ='<vdnScope><name>' + tz_name + '</name><clusters><cluster><cluster><objectId>'+ tz_cluster +'</objectId></cluster></cluster></clusters><controlPlaneMode>'+tzcontrolPlaneMode+'</controlPlaneMode></vdnScope>'
    conn = httplib.HTTPSConnection(nsxMgrIp, nsxMgrPort)
    conn.request('POST', 'https://' + nsxMgrIp + '/api/2.0/vdn/scopes',xml_string,headers)
    response = conn.getresponse()
    print str(response.read())
    if response.status != 201:
            print "     "+str(response.status) + "There was a problem, Transport Zone NOT created "
            exit(1)
    else:
            tz_id=response.read()
            print "     Transport Zone named "+tz_name+", with ID="+tz_id+","+" Created Successfully"
            return tz_id
   
def main():
    
    # Register NSX Manager to a vCenter Server
    print "-----Begin NSX vSphere installation-----"
    print "   Connecting NSX Manager to vCenter . . . "
    resgister_nsxmgr(computeVcIp,computeVcUser,computeVcPass)

    # If user wants , configure SSO.
    # This will use the SSO instance on the compute vCenter box we paired to NSX Manager in previous step. If SSO instance is different use different Function parameters and associated variables
    # for VC IP,VC User, and VC Password
    if configureSSO == True:
        print "-----SSO configuration on NSX Manager-----"
        configure_sso(computeVcIp,computeVcUser,computeVcPass)
    else:
        print "   Skipping SSO configuration..."
    
    # Create IP Pool for NSX Controllers in Management server range
    print "-----Begin Management IP Pool creation for Controllers-----"
    mgtIpPool = add_ippool ('Controller IP Pool',mgtIpRangeMaskLength,mgtIpRangeGw,mgtIpRangeDns1,mgtIpRangeDns1,mgtIpRangeStart,mgtIpRangeStop)

    # Create Controllers
    print "-----Begin Controller deployment-----"
    for x in range(0,nsxControllerQty):
        ctlName=('Controller-'+str(x))
        ctlDeployJobId = add_controller (ctlName,mgtIpPool,ctlClusterId,ctlDatastoreId,ctlNetworkId,nsxMgrPassword)
    
        # Query the status of Controller deployment task
        jobStatus = 'Started'
        while jobStatus != 'Failure':
             print '   Status for Controller deployment job '+ctlDeployJobId +' for '+ctlName+' is ' + jobStatus
             print '   Waiting ' + str(jobpollingInterval) + ' seconds to recheck the Deployment job status.'
             time.sleep(jobpollingInterval)
             jobStatus = query_controllerDeploy(ctlDeployJobId)
             if jobStatus == 'Success':
                 print '   Sucessfuly deployed  '+ ctlName+', Job ID=' +ctlDeployJobId +' Job Status=' + jobStatus
                 break
             else:
                 continue

    # Prepare Cluster for VXLAN and install kernel Modules.
    print "-----Begin vxlan, dfw, ldr Cluster VIB installation-----"
    clusterPrepJobId = prepare_cluster(computeCluster)
    print '   VXLAN preparation of cluster ' +computeCluster +' was started using job ID '+clusterPrepJobId

    # Query the status of VXLAN deployment task
    vxlanjobStatus = 'Started'
    while vxlanjobStatus != 'Failure':
        print '   Status for VXLAN preparation job '+clusterPrepJobId +' is ' + vxlanjobStatus
        print '   Waiting ' + str(jobpollingInterval) + ' seconds to recheck the VXLAN Cluster preparation status.'
        time.sleep(jobpollingInterval)
        # vxlanjobStatus = query_nsxjob(clusterPrepJobId)
        vxlanjobStatus = query_nsxjob(clusterPrepJobId)
        if vxlanjobStatus == 'COMPLETED':
            print '   Sucessfuly configured '+ computeCluster+' for vxlan, Job ID=' +clusterPrepJobId +' Job Status=' + vxlanjobStatus
            break
        else:
            continue
    
    # Create IP Pool for VXLAN vTEPs 
    print "-----Begin VXLAN IP Pool creation for vTEPs-----"
    vxlanIpPoolId = add_ippool ('vxlan vTep IP Pool',computeIpRangeMaskLength,computeIpRangeGw,computeIpRangeDns1,computeIpRangeDns1,computeIpRangeStart,computeIpRangeStop)

    # Create VXLAN Segment Range and if needed Multicast Range
    print "-----Begin creation of vxlan segment range-----"
    create_segmentrange('5000', '8000')

    # Create VXLAN Segment Range and if needed Multicast Range
    print '-----Begin VXLAN configuration on Compute Cluster-----'
    configure_cluster(computeCluster,vxlanDvsId,vxlanVtepVlanId,vxlanVtepTeaming,vxlanIpPoolId,'1500')

    # Call Create TZ Function
    time.sleep(60)
    print "-----Begin creation of Transport Zone-----"
    tz_id = create_tz(tzName,computeCluster,vxlanReplicationMode)

    # Complete installation
    print '-----END Succesfully installed NSX vSphere-----'

main()


