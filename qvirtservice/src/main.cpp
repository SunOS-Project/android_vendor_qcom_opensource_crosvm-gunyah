/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "VirtualizationService.h"
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

using aidl::vendor::qti::qvirt::VirtualizationService;
using aidl::vendor::qti::qvirt::VirtualMachine;

int main(int argc, char **argv) {
    ABinderProcess_setThreadPoolMaxThreadCount(12);
    ABinderProcess_startThreadPool();

    auto virt = ndk::SharedRefBase::make<VirtualizationService>(argc,argv);
    const std::string virtName = std::string() + VirtualizationService::descriptor + "/default";
    if(virt == nullptr)
    {
        ALOGE("VirtualizationService object is null, Failed to register");
    }
    else
    {
        if(virt->asBinder() == nullptr)
        {
            ALOGE("VirtualizationService binder object is null");
        }
        else
        {
            binder_status_t status = AServiceManager_addService(virt->asBinder().get(),
                    virtName.c_str());
            CHECK_EQ(status, STATUS_OK);
            ALOGI("Virtualization service registered");
            ABinderProcess_joinThreadPool();
        }
    }

    return EXIT_FAILURE;

}