/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "VirtualMachine.h"
#include<thread>
#include <sys/wait.h>
#include <android-base/properties.h>

using android::base::WaitForProperty;

namespace aidl {
namespace vendor {
namespace qti {
namespace qvirt {

void VirtualMachine::handleBinderDeath(OnBinderDiedContext* context) {
    std::unique_lock<std::mutex> lk(vmMutex);

    VM_LOGI("Attempting to clear client CallbackObject for %s with pid = %ld, uid = %ld",
            vmInstance.vmName_.c_str(), context->pid, context->uid);

    VM_LOGV("Finding %s callbackobject with OnBinderDiedContext: %p, clientId: %p, pid: %ld, "
            "uid: %ld", vmInstance.vmName_.c_str(), context, context->clientId, context->pid,
            context->uid);

    auto found = std::find_if (vmInstance.virtualMachineCallbacks_.begin(),
            vmInstance.virtualMachineCallbacks_.end(),
            [=](const auto& it) { return static_cast<AIBinder*>(it->asBinder().get()) ==
            context->clientId; });

    if (found != vmInstance.virtualMachineCallbacks_.end())
    {
        vmInstance.virtualMachineCallbacks_.erase(found);
        mOnBinderDiedContexts.erase(context->clientId);
        VM_LOGI("Cleared client CallbackObject for %s", vmInstance.vmName_.c_str());
    }
    else
    {
        VM_LOGI("client CallbackObject not found");
    }

}

void VirtualMachine::onBinderDied(void* cookie) {

    VM_LOGI("Received Binder died Notification");
    OnBinderDiedContext* context = reinterpret_cast<OnBinderDiedContext*>(cookie);
    if (context != NULL)
    {
        if (context->server == nullptr) {
            VM_LOGE("OnBinderDied: context->server is NULL");
        }
        else {
            context->server->handleBinderDeath(context);
        }
    }
}

ndk::ScopedAStatus VirtualMachine::registerCallback(
        const std::shared_ptr<IVirtualMachineCallback>& in_callback) {

    VM_LOGI("Requested Callback registration for %s from pid = %ld, uid = %ld",
            vmInstance.vmName_.c_str(), AIBinder_getCallingPid(), AIBinder_getCallingUid());

    if (in_callback == nullptr)
    {
        VM_LOGE("RegisterCallback: Callback Object is null");
        return ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    }
    else
    {
        std::unique_lock<std::mutex> lk(vmMutex);
        ndk::SpAIBinder binder = in_callback->asBinder();

        if (binder == nullptr)
        {
            VM_LOGE("RegisterCallback: Callback Binder object is null");
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }

        AIBinder* clientId = binder.get();

        //check for duplicate entries
        auto check = std::find_if (vmInstance.virtualMachineCallbacks_.begin(),
                vmInstance.virtualMachineCallbacks_.end(),
                [=](const auto& it) { return clientId ==
                static_cast<AIBinder*>(it->asBinder().get()); });

        if (check != vmInstance.virtualMachineCallbacks_.end())
        {
            VM_LOGE("Duplicate request from CallbackObject for %s with pid = %ld, uid = %ld",
                    vmInstance.vmName_.c_str(), AIBinder_getCallingPid(), AIBinder_getCallingUid());
            return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(EX_ILLEGAL_ARGUMENT,
                    "The callback is already registered");
        }

        AIBinder_DeathRecipient* mDeathRecipient = AIBinder_DeathRecipient_new(&onBinderDied);
        std::unique_ptr<OnBinderDiedContext> context = std::make_unique<OnBinderDiedContext>(
                OnBinderDiedContext{.server = this, .clientId = clientId,
                .pid = AIBinder_getCallingPid(), .uid = AIBinder_getCallingUid()});

        if (context == nullptr)
        {
            VM_LOGE("OnBinderDiedContext is NULL, Failed to register death notification for %s "
                    "client Callback with pid = %ld, uid = %ld", vmInstance.vmName_.c_str(),
                    AIBinder_getCallingPid(), AIBinder_getCallingUid());
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        else
        {
            VM_LOGV("RegisterCallback: pid = %ld, uid = %ld, OnBinderDiedContext: %p, ClientId: %p"
                    , AIBinder_getCallingPid(), AIBinder_getCallingUid(),
                    static_cast<void*>(context.get()), clientId);

            binder_status_t status = AIBinder_linkToDeath(clientId, mDeathRecipient,
                    static_cast<void*>(context.get()));

            if (STATUS_OK != status)
            {
                VM_LOGE("Failed to register death notification for %s client Callback with "
                        "pid = %ld, uid = %ld", vmInstance.vmName_.c_str(), AIBinder_getCallingPid()
                        , AIBinder_getCallingUid());
                return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(EX_ILLEGAL_STATE,
                        "The given callback is dead");
            }
            else
            {
               VM_LOGI("death notification registered succesfully for %s client Callback with "
                        "pid = %ld, uid = %ld", vmInstance.vmName_.c_str(), AIBinder_getCallingPid()
                        , AIBinder_getCallingUid());
            }

            // Insert into a map to keep the context object alive.
            mOnBinderDiedContexts[clientId] = std::move(context);
            vmInstance.virtualMachineCallbacks_.emplace_back(in_callback);
            VM_LOGI("Callback registered succesfully for %s client Callback with pid = %ld, "
                    "uid = %ld", vmInstance.vmName_.c_str(), AIBinder_getCallingPid(),
                    AIBinder_getCallingUid());
        }

    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualMachine::getState(VirtualMachineState* virtualMachineState) {

    VM_LOGI("Requested getState for %s from pid = %ld", vmInstance.vmName_.c_str(),
            AIBinder_getCallingPid());
    std::unique_lock<std::mutex> lk(vmMutex);
    *virtualMachineState = vmInstance.vmstate_;
    VM_LOGI("getState: %s state is %s", vmInstance.vmName_.c_str(),
            getStatetoStr(vmInstance.vmstate_).c_str());

    return ndk::ScopedAStatus::ok();
}

static int terminate(const int &pid, bool flag = false) {

    int status;
    if (flag)
    {
        if (waitpid(pid, &status, WNOHANG|WUNTRACED) == 0)
        {
            VM_LOGI("Sending 'SIGKILL' signal to PID = %d", pid);
            kill(pid, SIGKILL);
        }
    }

    waitpid(pid, &status, WNOHANG|WUNTRACED);
    if (WIFEXITED(status) && WEXITSTATUS(status))
    {
        VM_LOGE("PID:%d exit not success, result :%d", pid, WEXITSTATUS(status));
        return -1;
    }
    if (WIFSIGNALED(status))
    {
        VM_LOGI("PID:%d terminated with signal: %d", pid, WTERMSIG(status));
        return -1;
    }

    return 0;
}

// Sets the VM's status property - vendor.qvirtmgr.<vm_name>.status.
void VirtualMachine::setVmStatusProperty(string vmStatus) {

    char vmStatusProp[BUFFER_MAX];
    snprintf(vmStatusProp, BUFFER_MAX, VM_STATUS_PROPERTY, vmInstance.vmName_.c_str());
    android::base::SetProperty(vmStatusProp, vmStatus.c_str());
}

static void printVMArgs(char **args) {

   std::string temp;
   while(*args != NULL)
   {
    temp += *args++;
    temp += " ";
   }

   if (!temp.empty()) {
       VM_LOGI("vm arguments: %s ", temp.c_str());
   } else {
       VM_LOGI("printVMArgs: NULL args ");
   }
}

// VM boot up set up and control operations.
int VirtualMachine::bootVM(int &pid, string &response) {

    int result = 0;
    if (vmInstance.vmParameters_.bootOperation_ == ControlState::START)
    {
        auto &diskParameters = vmInstance.vmParameters_.disk_;

        if (vmInstance.vmParameters_.vmBinary_.empty())
        {
            response = "required arguments missing";
            VM_LOGE("%s required arguments missing", vmInstance.vmName_.c_str());
            return -1;
        }

        const char* path = vmInstance.vmParameters_.vmBinary_.c_str();
        const char* args[diskParameters.size() + 3];
        int i = 0;
        args[i] = path;

        char disk_args[diskParameters.size()][BUFFER_MAX];
        if (!diskParameters.empty())
        {
            uint32_t index = 0;
            do
            {
                snprintf(disk_args[index], BUFFER_MAX, VM_DISK_ARGUMENT,
                        diskParameters[index].image_.c_str(), diskParameters[index].label_.c_str(),
                        diskParameters[index].readWrite_ ? "true" : "false");
                args[++i] = disk_args[index];
            } while(++index < diskParameters.size());
        }
        char  vmNameParam[BUFFER_MAX];
        string vmName = vmInstance.vmName_.c_str();
        snprintf(vmNameParam, BUFFER_MAX, VM_NAME_ARGUMENT, vmName.c_str());
        args[++i] = vmNameParam;
        args[++i] = nullptr;

        pid = fork();

        if (pid == 0)
        {
            if (verbose) printVMArgs(const_cast<char**>(args));
            int execResult = execv(path, const_cast<char**>(args));
            if ( execResult < 0)
            {
                response = "exec to qcrosvm failed";
                VM_LOGI("+----------------------------------------+");
                VM_LOGI("\t%s: launch failed - errno=%s, exiting...\t", vmInstance.vmName_.c_str(),
                        strerror(errno));
                VM_LOGI("+----------------------------------------+");
            }

            // Exit from the child process,
            // do not continue.
            _exit(EXIT_FAILURE);
        }
        else if (pid < 0)
        {
            response = "Fork failed";
            VM_LOGE("Fork failed = %s", strerror(errno));
            result = -1;
        }
        else if (pid > 0)
        {
            // Sleep/Wait for qvirt to boot
            sleep(vmInstance.vmParameters_.bootWaitTime_);
        }

        int temp = terminate(pid, false);
        if (temp != 0)
        {
            response = "qcrosvm exited unexpectedly";
            VM_LOGE("qcrosvm exited unexpectedly for %s", vmInstance.vmName_.c_str());
            result = pid = -1;
        }

    }

    return result;
}

unsigned char VirtualMachine::bootSequence(string &response) {

    int pid = -1;
    int bootTry = 0, vmFD = 0;
    int sequenceResult = -1;
    string response_local = "";
    do
    {
        vmFD = bootVM(pid,response_local);
        if (vmFD == -1)
        {
            VM_LOGE("VM boot operation failed for '%s', try again...", vmInstance.vmName_.c_str());
            sleep(vmInstance.vmParameters_.bootWaitTime_);
            continue;
        } else {
            sequenceResult = 0;
        }

        VM_LOGI("VM boot operation completed for '%s'", vmInstance.vmName_.c_str());

        // Success, exit
        break;
    } while(bootTry++ < vmInstance.vmParameters_.bootTryCount_);

    if (sequenceResult != 0)
    {
        response = response_local;
        VM_LOGI("'%s' terminated!!!, retried: %d", vmInstance.vmName_.c_str(),
                vmInstance.vmParameters_.bootTryCount_);
        return -1;
    }

    if (pid != -1)
    {
        vmInstance.vmParameters_.pid_ = pid;
        VM_LOGV("'%s' vmmgr pid = %d", vmInstance.vmName_.c_str(), vmInstance.vmParameters_.pid_);
    }

    return 0;
}

int VirtualMachine::launchVM(string &response) {

    VM_LOGI("Requested launchVM for %s", vmInstance.vmName_.c_str());

    if (vmInstance.vmstate_== VirtualMachineState::RUNNING) {
        VM_LOGI("%s is already in running state", vmInstance.vmName_.c_str());
        return 0;
    }

    int result = 0;
    result = bootSequence(response);

    if (result == 0) {
        VM_LOGI("'%s' launch COMPLETED!!", vmInstance.vmName_.c_str());
    } else {
        VM_LOGE("'%s' launch FAILED!!", vmInstance.vmName_.c_str());
    }

    return result;
}

void VirtualMachine::launch_autostartVMs() {

    VM_LOGV("In launch_autostartVMs() for %s", vmInstance.vmName_.c_str());
    //waiting for boot complete
    int result = 0;
    string response;

    if (!vmInstance.vmParameters_.noFSDependency_)
    {
        if (!WaitForProperty("sys.boot_completed", "1",
                std::chrono::seconds(vmInstance.vmParameters_.bootCompleteTimeout_))) {
            VM_LOGE("timed out checking for sys.boot_completed");
            result = -1;
            response = "timed out checking for sys.boot_completed";
        } else
            VM_LOGI("system boot completed");
    }
    else
    {
       VM_LOGI("%s: file system check skipped", vmInstance.vmName_.c_str());
    }

    std::unique_lock<std::mutex> lk(vmMutex);
    if (result == 0)
    {
        result = launchVM(response);
        if (result != 0)
        {
            VM_LOGE("launch_autostartVMs: %s launch failed with reason: %s",
                    vmInstance.vmName_.c_str(), response.c_str());
        }
    }
    else
    {
        VM_LOGE("launch_autostartVMs: %s launch failed with reason: %s",
                vmInstance.vmName_.c_str(), response.c_str());
    }
    //autostart attempt done
    autostart_done = true;
}

ndk::ScopedAStatus VirtualMachine::start() {

    VM_LOGV("Requested start for %s from pid = %ld ", vmInstance.vmName_.c_str(),
            AIBinder_getCallingPid());

    std::unique_lock<std::mutex> lk(vmMutex);

    bool startVm = vmInstance.vmParameters_.isEnabled_ &&
            vmInstance.vmParameters_.on_demand_start_supported;

    if (!startVm)
    {
        VM_LOGE("Request received from pid = %ld to start a Vm that doesn't support on-demand start"
                ", rejecting it", AIBinder_getCallingPid());

        VM_LOGV("isEnabled: %d, on_demand_start_supported: %d ", vmInstance.vmParameters_.isEnabled_
                , vmInstance.vmParameters_.on_demand_start_supported);

        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    if (vmInstance.vmParameters_.autostart && !vmInstance.vmParameters_.noFSDependency_ &&
            !autostart_done)
    {
        VM_LOGE("autostart enabled for this VM, requested start from pid = %ld while bootup ongoing"
                ", rejecting it", AIBinder_getCallingPid());

        VM_LOGV("autostart: %d, FSDependency: %d, autostart_done: %d",
                vmInstance.vmParameters_.autostart, !vmInstance.vmParameters_.noFSDependency_,
                autostart_done);

        return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(ERROR_VM_START,
                "autostart enabled for this VM, requested start while bootup ongoing");
    }

    if (vmInstance.vmstate_== VirtualMachineState::STOPPED) {
        VM_LOGE("Request received from pid = %ld to start a Vm which is in stopped state, rejecting"
                "it", AIBinder_getCallingPid());
        return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(ERROR_VM_START,
                "Cannot start a VM which is in STOPPED state");
    }

    string response;
    int result = launchVM(response);
    if (result != 0)
    {
        VM_LOGI("start: %s launch failed with reason: %s", vmInstance.vmName_.c_str(),
                response.c_str());
        return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(ERROR_VM_START,
                response.c_str());
    }

    return ndk::ScopedAStatus::ok();
}

void VirtualMachine::notify_clients(VirtualMachineState vmState) {

    int len = vmInstance.virtualMachineCallbacks_.size();

    if (len == 0)
    {
        VM_LOGI("No clients registered for %s callback yet", vmInstance.vmName_.c_str());
    }
    else
    {
        VM_LOGI("Notifying %d clients of %s", len, vmInstance.vmName_.c_str());
    }

    for (int i = 0; i < len; i++)
    {
        auto status = vmInstance.virtualMachineCallbacks_[i]->onStatusChanged(vmState);

        if (status.isOk()) {
            VM_LOGV("notify_clients: %s-CallbackObject[ClientId: %p]->onStatusChanged(%s): sucess",
                    vmInstance.vmName_.c_str(), static_cast<AIBinder*>(
                    vmInstance.virtualMachineCallbacks_[i]->asBinder().get()),
                    getStatetoStr(vmState).c_str());

        } else {
            VM_LOGV("notify_clients: %s-CallbackObject[ClientId: %p]->onStatusChanged(%s): failed",
                    vmInstance.vmName_.c_str(), static_cast<AIBinder*>(
                    vmInstance.virtualMachineCallbacks_[i]->asBinder().get()),
                    getStatetoStr(vmState).c_str());
        }
    }
}

void VirtualMachine::notify_clients_locked(string EVENT) {

    std::unique_lock<std::mutex> lk(vmMutex);
    if (EVENT == "create")
    {
        VM_LOGI("Event = create received for %s, state change to RUNNING",
                vmInstance.vmName_.c_str());
        vmInstance.vmstate_ = {VirtualMachineState::RUNNING};
        setVmStatusProperty("RUNNING");
    }
    else if (EVENT == "destroy")
    {
        VM_LOGI("Event = destroy received for %s, state change to STOPPED",
                vmInstance.vmName_.c_str());
        vmInstance.vmstate_ = {VirtualMachineState::STOPPED};
        setVmStatusProperty("STOPPED");
    }
    notify_clients(vmInstance.vmstate_);
}
}
}
}
}
