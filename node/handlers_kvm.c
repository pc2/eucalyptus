#include <stdio.h>
#include <stdlib.h>
#define __USE_GNU /* strnlen */
#include <string.h> /* strlen, strcpy */
#include <time.h>
#include <sys/types.h> /* fork */
#include <sys/wait.h> /* waitpid */
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h> /* SIGINT */

#include "ipc.h"
#include "misc.h"
#include <handlers.h>
#include <storage.h>
#include <eucalyptus.h>
#include <euca_auth.h>

/* coming from handlers.c */
extern sem * hyp_sem;
extern sem * inst_sem;
extern bunchOfInstances * global_instances;

#define HYPERVISOR_URI "qemu:///system"

static int doInitialize (struct nc_state_t *nc) 
{
	logprintfl(EUCADEBUG, "doInitialized() invoked\n");

	/* set up paths of Eucalyptus commands NC relies on */
	snprintf (nc->gen_libvirt_cmd_path, CHAR_BUFFER_SIZE, EUCALYPTUS_GEN_KVM_LIBVIRT_XML, nc->home, nc->home);
	snprintf (nc->get_info_cmd_path, CHAR_BUFFER_SIZE, EUCALYPTUS_GET_KVM_INFO,  nc->home, nc->home);
	strcpy(nc->uri, HYPERVISOR_URI);
	nc->convert_to_disk = 1;

	return OK;
}

static int
getResources(	struct nc_state_t *nc,
		long long *cores,
		long long *memory) {
	char *s = NULL;
        
	s = system_output (nc->get_info_cmd_path);
#define GET_VALUE(name,var) \
	if (get_value (s, name, &var)) { \
		logprintfl (EUCAFATAL, "error: did not find %s in output from %s\n", name, nc->get_info_cmd_path); \
		free (s); \
		return ERROR_FATAL; \
	}

	GET_VALUE("nr_cores", *cores);
	GET_VALUE("total_memory", *memory);
	/* we leave 256M to the host  */
	*memory -= 256;

	return OK;
}

static int
doRunInstance (	struct nc_state_t *nc,
		ncMetadata *meta,
		char *instanceId,
		char *reservationId, ncInstParams *params, 
		char *imageId, char *imageURL, 
		char *kernelId, char *kernelURL, 
		char *ramdiskId, char *ramdiskURL, 
		char *keyName, 
		char *privMac, char *pubMac, int vlan, 
		char *userData, char *launchIndex, char **groupNames,
		int groupNamesSize, ncInstance **outInst)
{
    ncInstance * instance = NULL;
    * outInst = NULL;
    int error;
    pid_t pid;
    ncNetConf ncnet;

    strcpy(ncnet.privateMac, privMac);
    strcpy(ncnet.publicMac, pubMac);
    ncnet.vlan = vlan;

    /* check as much as possible before forking off and returning */
    sem_p (inst_sem);
    instance = find_instance (&global_instances, instanceId);
    sem_v (inst_sem);
    if (instance) {
        logprintfl (EUCAFATAL, "Error: instance %s already running\n", instanceId);
        return 1; /* TODO: return meaningful error codes? */
    }
    if (!(instance = allocate_instance (instanceId, 
                                        reservationId,
                                        params, 
                                        imageId, imageURL,
                                        kernelId, kernelURL,
                                        ramdiskId, ramdiskURL,
                                        instance_state_names[PENDING], 
                                        PENDING, 
                                        meta->userId, 
                                        &ncnet, keyName,
                                        userData, launchIndex, groupNames, groupNamesSize))) {
        logprintfl (EUCAFATAL, "Error: could not allocate instance struct\n");
        return 2;
    }
    instance->state = BOOTING; /* TODO: do this in allocate_instance()? */

    sem_p (inst_sem); 
    error = add_instance (&global_instances, instance);
    sem_v (inst_sem);
    if ( error ) {
        free_instance (&instance);
        logprintfl (EUCAFATAL, "Error: could not save instance struct\n");
        return error;
    }

    instance->launchTime = time (NULL);
    instance->params.memorySize = params->memorySize;
    instance->params.numberOfCores = params->numberOfCores;
    instance->params.diskSize = params->diskSize;
    strcpy (instance->ncnet.privateIp, "0.0.0.0");
    strcpy (instance->ncnet.publicIp, "0.0.0.0");

    /* do the potentially long tasks in a thread */
    pthread_attr_t* attr = (pthread_attr_t*) malloc(sizeof(pthread_attr_t));
    pthread_attr_init(attr);
    pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);

    if ( pthread_create (&(instance->tcb), NULL, startup_thread, (void *)instance) ) {
        pthread_attr_destroy(attr);
        logprintfl (EUCAFATAL, "failed to spawn a VM startup thread\n");
        sem_p (inst_sem);
        remove_instance (&global_instances, instance);
        sem_v (inst_sem);
        free_instance (&instance);
        return 1;
    }
    pthread_attr_destroy(attr);

    * outInst = instance;
    return 0;

}

/* thread that does the actual reboot */
static void * rebooting_thread (void *arg) 
{
    virConnectPtr *conn;
    ncInstance * instance = (ncInstance *)arg;

    char xml_path [1024];
    snprintf (xml_path, 1024, "%s/%s/%s/libvirt.xml", scGetInstancePath(), instance->userId, instance->instanceId);
    char * xml = file2str (xml_path);
    if (xml == NULL) {
        logprintfl (EUCAERROR, "cannot obtain XML file %s\n", xml_path);
        return NULL;
    }

    conn = check_hypervisor_conn();
    if (! conn) {
        logprintfl (EUCAFATAL, "cannot restart instance %s, abandoning it\n", instance->instanceId);
        change_state (instance, SHUTOFF);
        free (xml);
        return NULL;
    }
    
    virDomainPtr dom = virDomainLookupByName(*conn, instance->instanceId);
    if (dom == NULL) {
        free (xml);
        return NULL;
    }

    sem_p (hyp_sem);
    // for KVM, must stop and restart the instance
    int error = virDomainDestroy (dom); // TODO: change to Shutdown?  TODO: is this synchronous?
    sem_v (hyp_sem);
    virDomainFree(dom);
    if (error) {
        free (xml);
        return NULL;
    }
    
    // domain is now shut down, create a new one with the same XML
    sem_p (hyp_sem); 
    dom = virDomainCreateLinux (*conn, xml, 0);
    sem_v (hyp_sem);
    free (xml);
    
    if (dom==NULL) {
        logprintfl (EUCAFATAL, "Failed to restart instance %s\n", instance->instanceId);
        change_state (instance, SHUTOFF);
        return NULL;
    }
    
    virDomainFree(dom);
    return NULL;
}

static int
doRebootInstance(	struct nc_state_t *nc,
			ncMetadata *meta,
			char *instanceId) 
{
    sem_p (inst_sem); 
    ncInstance *instance = find_instance (&global_instances, instanceId);
    sem_v (inst_sem);
    if ( instance == NULL ) {
        logprintfl (EUCAERROR, "cannot find instance %s\n", instanceId);
        return ERROR;
    }
    
    pthread_t tcb;
    // since shutdown/restart may take a while, we do them in a thread
    if ( pthread_create (&tcb, NULL, rebooting_thread, (void *)instance) ) {
        logprintfl (EUCAFATAL, "failed to spawn a reboot thread\n");
        return ERROR_FATAL;
    }
    
    return OK;
}

static int
doGetConsoleOutput(	struct nc_state_t *nc,
			ncMetadata *meta,
			char *instanceId,
			char **consoleOutput) {
  char *console_output;
  char console_file[1024];
  int rc, fd;
  struct stat statbuf;

  *consoleOutput = NULL;

  // for KVM, read the console output from a file, encode it, and return
  console_output = malloc(64 * 1024);
  if (console_output == NULL) {
    return(1);
  }
  
  snprintf(console_file, 1024, "%s/%s/%s/console.log", scGetInstancePath(), meta->userId, instanceId);
  
  rc = stat(console_file, &statbuf);
  if (rc < 0) {
    logprintfl(EUCAERROR, "cannot stat console_output file '%s'\n", console_file);
    if (console_output) free(console_output);
    return(1);
  }
  
  fd = open(console_file, O_RDONLY);
  if (fd < 0) {
    logprintfl(EUCAERROR, "cannot open '%s' read-only\n", console_file);
    if (console_output) free(console_output);
    return(1);
  }
  
  bzero(console_output, 64*1024);
  rc = read(fd, console_output, (64*1024)-1);
  close(fd);
  
  *consoleOutput = base64_enc((unsigned char *)console_output, strlen(console_output));
  if (console_output) free(console_output);
  return(0);
}

static int
doAttachVolume (	struct nc_state_t *nc,
			ncMetadata *meta,
			char *instanceId,
			char *volumeId,
			char *remoteDev,
			char *localDev)
{
    int ret = OK;
    ncInstance *instance;
    virConnectPtr *conn;
    char localDevReal[32], localDevTag[256];

    // fix up format of incoming local dev name, if we need to
    ret = convert_dev_names (localDev, localDevReal, localDevTag);
    if (ret)
        return ret;

    // find the instance record
    sem_p (inst_sem); 
    instance = find_instance(&global_instances, instanceId);
    sem_v (inst_sem);
    if ( instance == NULL ) 
        return NOT_FOUND;

    /* try attaching to the KVM domain */
    conn = check_hypervisor_conn();
    if (conn) {
        virDomainPtr dom = virDomainLookupByName(*conn, instanceId);
        if (dom) {

            int err = 0;
            char xml [1024];
            snprintf (xml, 1024, "<disk type='block'><driver name='phy'/><source dev='%s'/><target dev='%s'/></disk>", remoteDev, localDevReal);

            /* protect KVM calls, just in case */
            sem_p (hyp_sem);
            err = virDomainAttachDevice (dom, xml);
            sem_v (hyp_sem);
            if (err) {
                logprintfl (EUCAERROR, "virDomainAttachDevice() failed (err=%d) XML=%s\n", err, xml);
                ret = ERROR;
            } else {
                logprintfl (EUCAINFO, "attached %s to %s in domain %s\n", remoteDev, localDevReal, instanceId);
            }
            virDomainFree(dom);
        } else {
            if (instance->state != BOOTING) {
                logprintfl (EUCAWARN, "warning: domain %s not running on hypervisor, cannot attach device\n", instanceId);
            }
            ret = ERROR;
        }
    } else {
        ret = ERROR;
    }

    if (ret==OK) {
        ncVolume * volume;

        sem_p (inst_sem);
        volume = add_volume (instance, volumeId, remoteDev, localDevTag);
        scSaveInstanceInfo(instance); /* to enable NC recovery */
        sem_v (inst_sem);
        if ( volume == NULL ) {
            logprintfl (EUCAFATAL, "ERROR: Failed to save the volume record, aborting volume attachment\n");
            return ERROR;
        }
    }

    return ret;
}

static int
doDetachVolume (	struct nc_state_t *nc,
			ncMetadata *meta,
			char *instanceId,
			char *volumeId,
			char *remoteDev,
			char *localDev,
			int force)
{
    int ret = OK;
    ncInstance * instance;
    virConnectPtr *conn;
    char localDevReal[32], localDevTag[256];

    // fix up format of incoming local dev name, if we need to
    ret = convert_dev_names (localDev, localDevReal, localDevTag);
    if (ret)
        return ret;

    // find the instance record
    sem_p (inst_sem); 
    instance = find_instance(&global_instances, instanceId);
    sem_v (inst_sem);
    if ( instance == NULL ) 
        return NOT_FOUND;
    if ( find_volume (instance, volumeId)==NULL )
        return NOT_FOUND;
    
    /* try attaching to the KVM domain */
    conn = check_hypervisor_conn();
    if (!conn) {
        ret = ERROR;

    } else {
        virDomainPtr dom = virDomainLookupByName(*conn, instanceId);
        if (dom) {
            int err = 0;
            char xml [1024];
            snprintf (xml, 1024, "<disk type='block'><driver name='phy'/><source dev='%s'/><target dev='%s'/></disk>", remoteDev, localDevReal);

            /* protect KVM calls, just in case */
            sem_p (hyp_sem);
            err = virDomainDetachDevice (dom, xml);
            sem_v (hyp_sem);
            if (err) {
	      logprintfl (EUCAERROR, "virDomainDetachDevice() failed (err=%d) XML=%s\n", err, xml);
	      ret = ERROR;
            } else {
                logprintfl (EUCAINFO, "detached %s as %s in domain %s\n", remoteDev, localDevReal, instanceId);
            }
            virDomainFree(dom);
        } else {
            if (instance->state != BOOTING) {
                logprintfl (EUCAWARN, "warning: domain %s not running on hypervisor, cannot detach device\n", instanceId);
            }
            ret = ERROR;
        }
    }

    if (ret==OK) {
        ncVolume * volume;

        sem_p (inst_sem);
        volume = free_volume (instance, volumeId, remoteDev, localDevTag);
        scSaveInstanceInfo(instance); /* to enable NC recovery */
        sem_v (inst_sem);
        if ( volume == NULL ) {
            logprintfl (EUCAFATAL, "ERROR: Failed to find and remove volume record, aborting volume detachment\n");
            return ERROR;
        }
    }
    
    return ret;
}

struct handlers kvm_libvirt_handlers = {
    .name = "kvm",
    .doInitialize        = doInitialize,
    .getResources        = getResources,
    .doDescribeInstances = NULL,
    .doRunInstance       = doRunInstance,
    .doTerminateInstance = NULL,
    .doRebootInstance    = doRebootInstance,
    .doGetConsoleOutput  = doGetConsoleOutput,
    .doDescribeResource  = NULL,
    .doStartNetwork      = NULL,
    .doPowerDown         = NULL,
    .doAttachVolume      = doAttachVolume,
    .doDetachVolume      = doDetachVolume
};

