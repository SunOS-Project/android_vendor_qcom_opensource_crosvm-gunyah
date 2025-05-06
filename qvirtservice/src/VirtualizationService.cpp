/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "VirtualizationService.h"
#include<thread>
#include <poll.h>
#include <fstream>
#include <json/json.h>
#include <cutils/uevent.h>
#include <cutils/properties.h>
#include <android-base/properties.h>

using android::base::WaitForProperty;
using aidl::vendor::qti::qvirt::VirtualMachine;

namespace aidl {
namespace vendor {
namespace qti {
namespace qvirt {

static void parse_event(const char *msg, struct uevent *uevent) {
    uevent->vm_name = "";
    uevent->EVENT = "";
    while (*msg) {
       if (!strncmp(msg, "EVENT=", 6)) {
           msg += 6;
           uevent->EVENT = msg;
       } else if (!strncmp(msg, "vm_name=", 8)) {
           msg += 8;
           uevent->vm_name = msg;
       }
       // advance to after the next \0
       while (*msg++);
    }
}

static void handle_uevent_event(std::map<std::string,
        std::shared_ptr<VirtualMachine> >& vmObject_map) {

    char msg[UEVENT_MSG_LEN + 2];
    int n;
    struct uevent uevent;

    while ((n = uevent_kernel_multicast_recv(uevent_fd, msg, UEVENT_MSG_LEN)) > 0) {
        if (n >= UEVENT_MSG_LEN) /* overflow -- discard */
            continue;

        msg[n] = '\0';
        msg[n + 1] = '\0';
        parse_event(msg, &uevent);
        if (uevent.EVENT != NULL && strlen(uevent.EVENT) != 0
                    && uevent.vm_name != NULL && strlen(uevent.vm_name) != 0)
        {
            VM_LOGI("uevent received is: EVENT = %s , vm_name = %s",
                    uevent.EVENT, uevent.vm_name);
            std::unique_lock<std::mutex> lk(mMutex_);
            if (vmObject_map.find(uevent.vm_name) == vmObject_map.end())
            {
                VM_LOGE("Invalid vm_name received from uevent");
                lk.unlock();
                continue;
            }
            std::shared_ptr<VirtualMachine> vmObject = vmObject_map[uevent.vm_name];
            lk.unlock();
            VM_LOGV("handle_uevent_event: Initiating request to notify state change to %s clients",
                    uevent.vm_name);
            if (vmObject != nullptr) {
                vmObject->notify_clients_locked(uevent.EVENT);
            }
        }
    }

}

static void uevent_listener(std::map<std::string,std::shared_ptr<VirtualMachine> >& vmObject_map){

    VM_LOGI("started uevent listener thread\n");
    uevent_fd = uevent_open_socket(64 * 1024, true);

    if (uevent_fd < 0) {
        VM_LOGE("uevent_open_socket() failed\n");
        return;
    }
    fcntl(uevent_fd, F_SETFL, O_NONBLOCK);
    pollfd ufd;
    ufd.events = POLLIN;
    ufd.fd = uevent_fd;

    while (true) {
        ufd.revents = 0;
        int nr = poll(&ufd, 1, -1);

        if (nr <= 0) {
            VM_LOGE("poll() of uevent socket failed, continuing");
            continue;
        }
        if (ufd.revents & POLLIN) {
            handle_uevent_event(vmObject_map);
        }
    }
}

int VirtualizationService::parseVMConfigFile() {

    string vendorConfigFile(VENDOR_CONFIG_FILE);

    // Attempt to open vendor-specific config file
    ifstream inputFile(vendorConfigFile, ifstream::in);

    if (!inputFile.is_open())
    {
        VM_LOGE("Couldn't open vendor vm config file (%s), aborting.", vendorConfigFile.c_str());
        return -1;
    }
    VM_LOGI("Using '%s' vm config file", vendorConfigFile.c_str());

    Json::CharReaderBuilder reader;
    Json::Value root;
    std::string err;

    reader["collectComments"] = false;
    if (!Json::parseFromStream(reader, inputFile, &root, &err))
    {
        VM_LOGE("Parsing configuration file '%s' failed with error: %s", vendorConfigFile.c_str(),
                err.c_str());

       // Close config file
       inputFile.close();
       return -1;
    }

    // Close config file
    inputFile.close();

    // Read root node
    const Json::Value& jsonVmConfig = root["qvirtmgr"];

    const Json::Value& jsonConfigArray = jsonVmConfig["vm_config"];
    if (!jsonVmConfig || !jsonConfigArray)
    {
        VM_LOGE("VM configurations found in '%s' is invalid", vendorConfigFile.c_str());
        return -1;
    }

    for (const Json::Value& jsonConfig : jsonConfigArray)
    {
        if (!jsonConfig.isMember("name") || jsonConfig["name"].isNull())
        {
            VM_LOGE("Missing value for vmName,skipping entry");
            continue;
        }

        if (!jsonConfig.isMember("enable") || !jsonConfig["enable"].isBool())
        {
            VM_LOGE("Missing or Invalid value for enable, skipping entry for %s",
                    jsonConfig["name"].asString().c_str());
            continue;
        }

        VirtualMachine::VmParameters vmParameters(jsonConfig["name"].asString(),
                jsonConfig["enable"].asBool());

        if (jsonConfig.isMember("autostart") && jsonConfig["autostart"].isBool())
        {
            vmParameters.autostart = jsonConfig["autostart"].asBool();
        }
        else
        {
            VM_LOGE("Missing or Invalid value for autostart, skipping entry for %s",
                    jsonConfig["name"].asString().c_str());
            continue;
        }

        if (jsonConfig.isMember("on_demand_start_supported") &&
                jsonConfig["on_demand_start_supported"].isBool())
        {
            vmParameters.on_demand_start_supported =
                    jsonConfig["on_demand_start_supported"].asBool();
        }

        if (jsonConfig.isMember("no_fs_dependency") && jsonConfig["no_fs_dependency"].isBool())
        {
            vmParameters.noFSDependency_ = jsonConfig["no_fs_dependency"].asBool();
        }
        else
        {
            VM_LOGE("Missing or Invalid value for no_fs_dependency, skipping entry for %s",
                    jsonConfig["name"].asString().c_str());
            continue;
        }

        if (jsonConfig.isMember("disk"))
        {
            // Read disk properties
            const Json::Value& jsonDiskArray = jsonConfig["disk"];

            bool diskparams = true;
            for (const Json::Value& jsonDisk : jsonDiskArray)
            {
                if (!jsonDisk.isMember("image") || !jsonDisk.isMember("label") ||
                        !jsonDisk.isMember("read_write") || !jsonDisk["read_write"].isBool() )
                {
                    diskparams = false;
                    break;
                }
                string image = jsonDisk["image"].asString();
                string label = jsonDisk["label"].asString();
                bool readWrite = jsonDisk["read_write"].asBool();

                vmParameters.disk_.emplace_back(image, label, readWrite);
            }
            if (!diskparams)
            {
                VM_LOGE("Missing or Invalid disk parameters, skipping entry for %s",
                        jsonConfig["name"].asString().c_str());
                continue;
            }
        }

        if (jsonConfig.isMember("try_count") && jsonConfig["try_count"].isUInt())
        {
            vmParameters.bootTryCount_ = jsonConfig["try_count"].asUInt();
        }

        if (jsonConfig.isMember("boot_wait_time") && jsonConfig["boot_wait_time"].isUInt())
        {
            vmParameters.bootWaitTime_ = jsonConfig["boot_wait_time"].asUInt();
        }
        else
        {
            VM_LOGE("Missing or Invalid value for boot_wait_time, skipping entry for %s",
                    jsonConfig["name"].asString().c_str());
            continue;
        }

        if (jsonConfig.isMember("boot_complete_timeout") &&
                jsonConfig["boot_complete_timeout"].isUInt())
        {
            vmParameters.bootCompleteTimeout_ = jsonConfig["boot_complete_timeout"].asUInt();
        }

        string temp("");

        if (jsonConfig.isMember("boot_ops"))
        {
            temp = jsonConfig["boot_ops"].asString();
            vmParameters.bootOperation_ = VirtualMachine::getControlState(temp);
            vmParameters.vmBinary_ = string(VM_BINARY_FILE);
        }
        else
        {
            VM_LOGE("Missing or Invalid value for boot_ops, skipping entry for %s",
                    jsonConfig["name"].asString().c_str());
            continue;
        }

        vmParameters_map.insert({vmParameters.vmName_, vmParameters});
    }
    VM_LOGI("Number of vm configurations = %lu", vmParameters_map.size());
    return 0;
}

std::shared_ptr<VirtualMachine> VirtualizationService::getVm_Internal(string in_vmName) {

    if (vmObject_map.find(in_vmName) != vmObject_map.end()) {
        return vmObject_map[in_vmName];
    }

    VM_LOGI("getVm_Internal: Creating vmObject for %s", in_vmName.c_str());
    std::shared_ptr<VirtualMachine> mVirtualMachine = SharedRefBase::make<VirtualMachine>();

    if (mVirtualMachine != nullptr) {
        mVirtualMachine->vmInstance.vmName_ = in_vmName;
        mVirtualMachine->verbose = verbose;
        mVirtualMachine->setVmStatusProperty("NOT_STARTED");
        mVirtualMachine->vmInstance.vmParameters_ = vmParameters_map[in_vmName];
        vmObject_map.insert({in_vmName, mVirtualMachine});
        VM_LOGV("size of vmObject map is %d", vmObject_map.size());
    }
    return mVirtualMachine;
}

static void autostarthandler(std::shared_ptr<VirtualMachine> virtualMachineObj)
{
    VM_LOGI("autostarthandler: Launching %s", virtualMachineObj->vmInstance.vmName_.c_str());
    virtualMachineObj->launch_autostartVMs();
    VM_LOGV("Exiting from autostarthandler for vm %s",
            virtualMachineObj->vmInstance.vmName_.c_str());
}

VirtualizationService::VirtualizationService(int argc, char **argv) {

    if (argc>1 && strcmp(argv[1],"-v") == 0)
    {
        verbose = true;
    }
    std::thread thread(uevent_listener, std::ref(vmObject_map));
    thread.detach();
    int state = parseVMConfigFile();
    if (state != 0)
    {
        exit(EXIT_FAILURE);
    }
    else
    {
        VM_LOGI("parsing vm config file success");
    }
    vector<std::thread> vmThreads_noFSDependent;
    vector<std::thread> vmThreads_FSDependent;

    for (auto i : vmParameters_map)
    {
        if (i.second.isEnabled_)
        {
            VM_LOGV("autoboot enabled for %s", i.first.c_str());

            std::unique_lock<std::mutex> lk(mMutex_);
            getVm_Internal(i.first);

            if (vmObject_map.find(i.first) == vmObject_map.end()) {
                VM_LOGE("vmObject not found for %s", i.first.c_str());
                continue;
            }

            if (i.second.autostart)
            {
                if (i.second.noFSDependency_) {
                    vmThreads_noFSDependent.push_back(std::thread(autostarthandler,
                            vmObject_map[i.first]));
                }
                else {
                    vmThreads_FSDependent.push_back(std::thread(autostarthandler,
                            vmObject_map[i.first]));
                }
            }

            lk.unlock();
        }
        else {
            char vmStatusProp[BUFFER_MAX];
            snprintf(vmStatusProp, BUFFER_MAX, VM_STATUS_PROPERTY, i.first.c_str());
            android::base::SetProperty(vmStatusProp, "NOT_STARTED");
        }
    }

    for (int i = 0; i < vmThreads_FSDependent.size(); i++)
    {
        vmThreads_FSDependent[i].detach();
    }

    for (int i = 0; i < vmThreads_noFSDependent.size(); i++)
    {
        vmThreads_noFSDependent[i].join();
    }
}

ndk::ScopedAStatus VirtualizationService::getVm(const std::string& in_vmName,
        std::shared_ptr<IVirtualMachine>* iVirtualMachine) {

    VM_LOGI("getVm: Requested vm handle for %s from pid = %ld", in_vmName.c_str(),
            AIBinder_getCallingPid());

    std::unique_lock<std::mutex> lk(mMutex_);

    if (vmParameters_map.find(in_vmName) == vmParameters_map.end())
    {
        VM_LOGE("getVm: Invalid vmName argument passed, rejecting request");
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    else if (!vmParameters_map[in_vmName].isEnabled_)
    {
        VM_LOGE("getVm: enabled bit is false for %s, rejecting request", in_vmName.c_str());
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    *iVirtualMachine = getVm_Internal(in_vmName);

    if (iVirtualMachine == nullptr)
    {
        VM_LOGE("getVm: VirtualMachineObject is null, rejecting request");
        return ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    }

    return ndk::ScopedAStatus::ok();

}

}
}
}
}
