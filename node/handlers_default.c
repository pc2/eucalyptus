/*
Copyright (c) 2009  Eucalyptus Systems, Inc.	

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by 
the Free Software Foundation, only version 3 of the License.  
 
This file is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.  

You should have received a copy of the GNU General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.
 
Please contact Eucalyptus Systems, Inc., 130 Castilian
Dr., Goleta, CA 93101 USA or visit <http://www.eucalyptus.com/licenses/> 
if you need additional information or have any questions.

This file may incorporate work covered under the following copyright and
permission notice:

  Software License Agreement (BSD License)

  Copyright (c) 2008, Regents of the University of California
  

  Redistribution and use of this software in source and binary forms, with
  or without modification, are permitted provided that the following
  conditions are met:

    Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. USERS OF
  THIS SOFTWARE ACKNOWLEDGE THE POSSIBLE PRESENCE OF OTHER OPEN SOURCE
  LICENSED MATERIAL, COPYRIGHTED MATERIAL OR PATENTED MATERIAL IN THIS
  SOFTWARE, AND IF ANY SUCH MATERIAL IS DISCOVERED THE PARTY DISCOVERING
  IT MAY INFORM DR. RICH WOLSKI AT THE UNIVERSITY OF CALIFORNIA, SANTA
  BARBARA WHO WILL THEN ASCERTAIN THE MOST APPROPRIATE REMEDY, WHICH IN
  THE REGENTS’ DISCRETION MAY INCLUDE, WITHOUT LIMITATION, REPLACEMENT
  OF THE CODE SO IDENTIFIED, LICENSING OF THE CODE SO IDENTIFIED, OR
  WITHDRAWAL OF THE CODE CAPABILITY TO THE EXTENT NEEDED TO COMPLY WITH
  ANY SUCH LICENSES OR RIGHTS.
*/
#include <stdio.h>
#include <stdlib.h>
#define __USE_GNU /* strnlen */
#include <string.h> /* strlen, strcpy */
#include <time.h>
#include <limits.h> /* INT_MAX */
#include <sys/types.h> /* fork */
#include <sys/wait.h> /* waitpid */
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/vfs.h> /* statfs */
#include <signal.h> /* SIGINT */

#include "ipc.h"
#include "misc.h"
#include <handlers.h>
#include <storage.h>
#include <eucalyptus.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <vnetwork.h>
#include <euca_auth.h>


/* coming from handlers.c */
extern sem * hyp_sem;
extern sem * inst_sem;
extern bunchOfInstances * global_instances;

static int
doInitialize (struct nc_state_t *nc) 
{
	return OK;
}

static int
doRunInstance (	struct nc_state_t *nc, ncMetadata *meta, char *instanceId,
		char *reservationId, ncInstParams *params, 
		char *imageId, char *imageURL, 
		char *kernelId, char *kernelURL, 
		char *ramdiskId, char *ramdiskURL, 
		char *keyName, char *privMac, char *pubMac, int vlan, 
		char *userData, char *launchIndex, 
		char **groupNames, int groupNamesSize, ncInstance **outInst)
{
	logprintfl(EUCAERROR, "no default for doRunInstance!\n");
	return ERROR_FATAL;
}

static int
doRebootInstance(struct nc_state_t *nc, ncMetadata *meta, char *instanceId) 
{    
	logprintfl(EUCAERROR, "no default for doRebootInstance!\n");
	return ERROR_FATAL;
}

static int
doGetConsoleOutput(	struct nc_state_t *nc, 
			ncMetadata *meta,
			char *instanceId,
			char **consoleOutput)
{
	logprintfl(EUCAERROR, "no default for doGetConsoleOutput!\n");
	return ERROR_FATAL;
}

static int
doTerminateInstance(	struct nc_state_t *nc,
			ncMetadata *meta,
			char *instanceId,
			int *shutdownState,
			int *previousState)
{
	ncInstance *instance, *vninstance;
	virConnectPtr *conn;
	int err;

	sem_p (inst_sem); 
	instance = find_instance(&global_instances, instanceId);
	sem_v (inst_sem);
	if (instance == NULL) 
		return NOT_FOUND;

	/* try stopping the KVM domain */
	conn = check_hypervisor_conn();
	if (conn) {
	        sem_p(hyp_sem);
	        virDomainPtr dom = virDomainLookupByName(*conn, instanceId);
		sem_v(hyp_sem);
		if (dom) {
			/* also protect 'destroy' commands, just in case */
			sem_p (hyp_sem);
			err = virDomainDestroy (dom);
			sem_v (hyp_sem);
			if (err==0) {
				logprintfl (EUCAINFO, "destroyed domain for instance %s\n", instanceId);
			}
			sem_p(hyp_sem);
			virDomainFree(dom); /* necessary? */
			sem_v(hyp_sem);
		} else {
			if (instance->state != BOOTING)
				logprintfl (EUCAWARN, "warning: domain %s to be terminated not running on hypervisor\n", instanceId);
		}
	} 

	/* change the state and let the monitoring_thread clean up state */
    sem_p (inst_sem);
    if (instance->state==BOOTING) {
        change_state (instance, CANCELED);
    } else {
        change_state (instance, SHUTOFF);
    }
    sem_v (inst_sem);
	*previousState = instance->stateCode;
	*shutdownState = instance->stateCode;

	return OK;
}

static int
doDescribeInstances(	struct nc_state_t *nc,
			ncMetadata *meta,
			char **instIds,
			int instIdsLen,
			ncInstance ***outInsts,
			int *outInstsLen)
{
	ncInstance *instance;
	int total, i, j, k;

	*outInstsLen = 0;
	*outInsts = NULL;

	sem_p (inst_sem);
	if (instIdsLen == 0) /* describe all instances */
		total = total_instances (&global_instances);
	else 
		total = instIdsLen;

	*outInsts = malloc(sizeof(ncInstance *)*total);
	if ((*outInsts) == NULL) {
		sem_v (inst_sem);
		return OUT_OF_MEMORY;
	}

	k = 0;
	for (i=0; (instance = get_instance(&global_instances)) != NULL; i++) {
		/* only pick ones the user (or admin)  is allowed to see */
		if (strcmp(meta->userId, nc->admin_user_id) 
				&& strcmp(meta->userId, instance->userId))
			continue;

		if (instIdsLen > 0) {
			for (j=0; j < instIdsLen; j++)
				if (!strcmp(instance->instanceId, instIds[j]))
					break;

			if (j >= instIdsLen)
				/* instance of not relavance right now */
				continue;
		}

		(* outInsts)[k++] = instance;
	}
	*outInstsLen = k;
	sem_v (inst_sem);

	return OK;
}

static int
doDescribeResource(	struct nc_state_t *nc,
			ncMetadata *meta,
			char *resourceType,
			ncResource **outRes)
{
    ncResource * res;
    ncInstance * inst;

    /* stats to re-calculate now */
    long long mem_free;
    long long disk_free;
    int cores_free;

    /* intermediate sums */
    long long sum_mem = 0;  /* for known domains: sum of requested memory */
    long long sum_disk = 0; /* for known domains: sum of requested disk sizes */
    int sum_cores = 0;      /* for known domains: sum of requested cores */


    *outRes = NULL;
    sem_p (inst_sem); 
    while ((inst=get_instance(&global_instances))!=NULL) {
        if (inst->state == TEARDOWN) continue; /* they don't take up resources */
        sum_mem += inst->params.memorySize;
        sum_disk += (inst->params.diskSize + SWAP_SIZE);
        sum_cores += inst->params.numberOfCores;
    }
    sem_v (inst_sem);
    
    disk_free = nc->disk_max - sum_disk;
    if ( disk_free < 0 ) disk_free = 0; /* should not happen */
    
    mem_free = nc->mem_max - sum_mem;
    if ( mem_free < 0 ) mem_free = 0; /* should not happen */

    cores_free = nc->cores_max - sum_cores; /* TODO: should we -1 for dom0? */
    if ( cores_free < 0 ) cores_free = 0; /* due to timesharing */

    /* check for potential overflow - should not happen */
    if (nc->mem_max > INT_MAX ||
        mem_free > INT_MAX ||
        nc->disk_max > INT_MAX ||
        disk_free > INT_MAX) {
        logprintfl (EUCAERROR, "stats integer overflow error (bump up the units?)\n");
        logprintfl (EUCAERROR, "   memory: max=%-10lld free=%-10lld\n", nc->mem_max, mem_free);
        logprintfl (EUCAERROR, "     disk: max=%-10lld free=%-10lld\n", nc->disk_max, disk_free);
        logprintfl (EUCAERROR, "    cores: max=%-10d free=%-10d\n", nc->cores_max, cores_free);
        logprintfl (EUCAERROR, "       INT_MAX=%-10d\n", INT_MAX);
        return 10;
    }
    
    res = allocate_resource ("OK", nc->mem_max, mem_free, nc->disk_max, disk_free, nc->cores_max, cores_free, "none");
    if (res == NULL) {
        logprintfl (EUCAERROR, "Out of memory\n");
        return 1;
    }
    *outRes = res;

    return OK;
}

static int
doPowerDown(	struct nc_state_t *nc,
		ncMetadata *ccMeta)
{
	char cmd[1024];
	int rc;

	snprintf(cmd, 1024, "%s /etc/init.d/powernap now", nc->rootwrap_cmd_path);
	logprintfl(EUCADEBUG, "saving power: %s\n", cmd);
	rc = system(cmd);
	rc = rc>>8;
	if (rc)
		logprintfl(EUCAERROR, "cmd failed: %d\n", rc);
  
	return OK;
}

static int
doStartNetwork(	struct nc_state_t *nc,
		ncMetadata *ccMeta, 
		char **remoteHosts, 
		int remoteHostsLen, 
		int port, 
		int vlan) {
	int rc, ret, i, status;
	char *brname;

	rc = vnetStartNetwork(nc->vnetconfig, vlan, NULL, NULL, &brname);
	if (rc) {
		ret = 1;
		logprintfl (EUCAERROR, "StartNetwork(): ERROR return from vnetStartNetwork %d\n", rc);
	} else {
		ret = 0;
		logprintfl (EUCAINFO, "StartNetwork(): SUCCESS return from vnetStartNetwork %d\n", rc);
		if (brname) free(brname);
	}
	logprintfl (EUCAINFO, "StartNetwork(): done\n");

	return (ret);
}

static int
doAttachVolume(	struct nc_state_t *nc,
		ncMetadata *meta,
		char *instanceId,
		char *volumeId,
		char *remoteDev,
		char *localDev)
{
	logprintfl(EUCAERROR, "no default for doAttachVolume!\n");
	return ERROR_FATAL;
}

static int
doDetachVolume(	struct nc_state_t *nc,
		ncMetadata *meta,
		char *instanceId,
		char *volumeId,
		char *remoteDev,
		char *localDev,
		int force)
{
	logprintfl(EUCAERROR, "no default for doDetachVolume!\n");
	return ERROR_FATAL;
}

static int doDescribeHardware ( struct nc_state_t *nc, 
				ncMetadata *meta, 
				ncHardwareInfo *hwinfo)
{
  virNodeInfo info;
  virConnectPtr *con = check_hypervisor_conn();
  
  sem_p (hyp_sem);
  if (virNodeGetInfo (*con, &info) != 0)
    return (-1);
  sem_v (hyp_sem);

  strcpy (hwinfo->model, info.model);
  hwinfo->memory = info.memory;
  hwinfo->cpus = info.cpus;
  hwinfo->mhz = info.mhz;
  hwinfo->nodes = info.nodes;
  hwinfo->sockets = info.sockets;
  hwinfo->cores = info.cores;
  hwinfo->threads = info.threads;

  return (0);
}

static int getNetworkUtilization (char *cmd, int *networkUtilization)
{
  if (perform_sensor_call (cmd, networkUtilization)!=0) {
    logprintfl (EUCAERROR, "can not get network utilization");
    *networkUtilization = 0;
    return (-1);
  }
  else
    return 0;
}

static int getHostUtilization (char *cmd, int *utilization)
{
  if (perform_sensor_call (cmd, utilization)!=0) {
    logprintfl (EUCAERROR, "can not get host utilization");
    *utilization = 0;
    return (-1);
  }
  else
    return 0;
}

static int getPowerConsumption (char *cmd, int *powerConsumption)
{
  if (perform_sensor_call (cmd, powerConsumption)!=0) {
    logprintfl (EUCAERROR, "can not get power consumption");
    *powerConsumption = 0;
    return (-1);
  }
  else
    return 0;
}

/*
static int getInstanceUtilization (ncInstanceUtilization *instanceUtilization[])
{
  int ret=OK;
  virConnectPtr *conn;
  conn = check_hypervisor_conn();
  
  if (conn)
    {
      int num_doms=0, dom_ids[MAXDOMS], i;
      virDomainPtr dom = NULL;

      logprintfl (EUCAINFO, "looking for existing domains\n");
	virSetErrorFunc (NULL, libvirt_error_handler);
	
      sem_p (hyp_sem);
      num_doms = virConnectListDomains(*conn, dom_ids, MAXDOMS);
      sem_v (hyp_sem);

      if (num_doms == 0) {
	logprintfl (EUCAINFO, "no currently running domains\n");
	return (0);
      } if (num_doms < 0) {
	logprintfl (EUCAWARN, "WARNING: failed to find out about running domains\n");
	return -1;
      }

      for ( i=0; i<num_doms; i++) {
	int num_vcpus;
	virVcpuInfo vcpu_info1[MAX_CORES_PER_INSTANCE];
	virVcpuInfo vcpu_info2[MAX_CORES_PER_INSTANCE];

	sem_p(hyp_sem);
	dom = virDomainLookupByID(*conn, dom_ids[i]);
	sem_v(hyp_sem);
	if (!dom) {
	  logprintfl (EUCAWARN, "WARNING: failed to lookup running domain #%d, ignoring it\n", dom_ids[i]);
	  continue;
	}
	
	num_vcpus = virDomainGetVcpus (dom, vcpu_info1, MAX_CORES_PER_INSTANCE, NULL, 0);
	sleep (1);
	num_vcpus = virDomainGetVcpus (dom, vcpu_info2, MAX_CORES_PER_INSTANCE, NULL, 0);

	if (num_vcpus != -1)
	  {
	    int j;
	    instanceUtilization[i]->numVcpus = num_vcpus;
	    for (j=0; j<num_vcpus; j++)
	      {
		// cpuTime is given in nanoseconds by libvirt
		instanceUtilization[i]->vcpuUtilization[j] = (double)(vcpu_info2->cpuTime - (double)vcpu_info1->cpuTime) / 1000000000.0;
	      }
	  }
	else
	  {
	    ret = -1;
	    return (ret);
	  }

	sem_p(hyp_sem);
	virDomainFree (dom);
	sem_v(hyp_sem);
      }
    }
  else
    {
      ret = -1;
    }

  return ret;
}
*/


static int doDescribeUtilization (struct nc_state_t *nc, 
				  ncMetadata *meta, 
				  ncUtilization *utilization)
{
  /*utilization->numInstances = getInstanceUtilization (&(utilization->instances));*/
  if (getNetworkUtilization (nc->network_utilization_sensor_cmd, &(utilization->networkUtilization)) != 0 || 
      getHostUtilization (nc->utilization_sensor_cmd, &(utilization->utilization))!=0 ||
      getPowerConsumption (nc->power_consumption_sensor_cmd, &(utilization->powerConsumption))!=0)
    {
      return (-1);
    }
  time(&(utilization->timePoint));

  /*if (utilization->numInstances == -1) {
    utilization->numInstances = 0;
    return (-1);
    }
    else*/
    return (0);
}

static int getRemoteURI (struct nc_state_t *nc, char *target, char *result, size_t max_result_size)
{
  /* TODO: Put URI format to eucalyptus.con */ 
  logprintfl(EUCADEBUG, "getRemoteURI() invoked\n");
  if (!strcmp(nc->H->name, "xen")) 
    snprintf(result, max_result_size, "xen+ssh://eucalyptus@%s", target);
  else if (!strcmp(nc->H->name, "kvm"))
    snprintf(result, max_result_size, "qemu+ssh://eucalyptus@%s/system", target);
  else {
    strncpy(result, target, max_result_size);
    result = strdup(target);
  }
  logprintfl(EUCADEBUG, "getRemoteURI(): result=%s\n", result); 
  return (OK);
}

static int doMigrateInstance(struct nc_state_t *nc, ncMetadata *meta, char *instanceId, char *target) 
{
  int ret=OK;
  char remoteURI[CHAR_BUFFER_SIZE];
  virConnectPtr *conn, dst;
  ncInstance *instance;

  logprintfl(EUCADEBUG, "doMigrateInstance() in default handler invoked\n");
  conn = check_hypervisor_conn();
 
  if (!conn) {
    logprintfl(EUCAERROR, "doMigrateInstance() cannot connect to hypervisor\n");
  }

  if (target || !strcmp(target, "")) {
    getRemoteURI(nc, target, remoteURI, CHAR_BUFFER_SIZE);
    logprintfl(EUCADEBUG, "doMigrateInstance(): connecting to remote hypervisor\n");
    dst = virConnectOpen(remoteURI);
    if (!dst) {
      logprintfl(EUCAERROR, "doMigrateInstance(): Connection to remote Hypervisor failed (URI: %s)\n", remoteURI);
    } else {
      logprintfl(EUCADEBUG, "doMigrateInstance(): Connected to %s\n", remoteURI);
    }
  } else {
    logprintfl(EUCAERROR, "doMigrateInstance(): no migration target\n");
    return (ERROR);
  }

  sem_p (inst_sem); 
  instance = find_instance(&global_instances, instanceId);
  sem_v (inst_sem);
  if (instance == NULL) {
    logprintfl(EUCAERROR, "doMigrateInstance(): instance not found\n");
    return (NOT_FOUND);
  }

  if (conn && dst) {
    sem_p(hyp_sem);
    virDomainPtr dom = virDomainLookupByName(*conn, instanceId);
    sem_v(hyp_sem);
    
    if (dom) {
      sem_p (hyp_sem);
      if (virDomainMigrate (dom, dst, VIR_MIGRATE_LIVE, NULL, NULL, 0))
	logprintfl (EUCAINFO, "doMigrateInstance(): migrated instance %s\n", instanceId);
      else 
	ret = ERROR;
      sem_v (hyp_sem);
    }
    else {
      logprintfl (EUCAWARN, "warning: domain %s to be migrated not running on hypervisor\n", instanceId);
      ret = ERROR;
    }
  }
 else {
   logprintfl(EUCAERROR, "doMigrateInstance(): Migrating %s failed\n", instanceId);
   ret = ERROR;
  }
 
  if (ret == OK) {
    sem_p (inst_sem); 
    instance = find_instance(&global_instances, instanceId);
    logprintfl(EUCADEBUG, "doMigrateInstance(): removing instance from global_instances\n");
    if (remove_instance (&global_instances, instance) != OK) {
      logprintfl(EUCAERROR, "doMigrateInstance(): cannot remove instance from global_instances\n");
      ret = ERROR;
    }
    sem_v (inst_sem);
  }
 
  return (ret);
}

static int doAdoptInstances(struct nc_state_t *nc, ncMetadata *meta)
{
  adopt_instances();
  return OK;
}

static int doDescribeInstanceUtilization(struct nc_state_t *nc, ncMetadata *meta, char *instanceId, int *utilization)
{
  char cmd[CHAR_BUFFER_SIZE];
  if (strcmp(nc->instance_utilization_sensor_cmd, "") == 0) {
    logprintfl(EUCAERROR, "No sensor for instance utilization\n");
    return (-1);
  } else {
    snprintf (cmd, CHAR_BUFFER_SIZE, "%s %s", nc->instance_utilization_sensor_cmd, instanceId);
    if (perform_sensor_call (cmd, utilization)!=0) {
      logprintfl (EUCAERROR, "cannot get instance utilization");
      *utilization = 0;
      return (-1);
    } else
      return (0);
  }
}

struct handlers default_libvirt_handlers = {
    .name = "default",
    .doInitialize        = doInitialize,
    .doDescribeInstances = doDescribeInstances,
    .doRunInstance       = doRunInstance,
    .doTerminateInstance = doTerminateInstance,
    .doRebootInstance    = doRebootInstance,
    .doGetConsoleOutput  = doGetConsoleOutput,
    .doDescribeResource  = doDescribeResource,
    .doStartNetwork      = doStartNetwork,
    .doPowerDown         = doPowerDown,
    .doAttachVolume      = doAttachVolume,
    .doDetachVolume      = doDetachVolume,
    .doDescribeHardware  = doDescribeHardware,
    .doDescribeUtilization = doDescribeUtilization,
    .doMigrateInstance   = doMigrateInstance,
    .doAdoptInstances    = doAdoptInstances,
    .doDescribeInstanceUtilization = doDescribeInstanceUtilization
};
