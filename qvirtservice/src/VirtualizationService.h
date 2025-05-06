/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include<aidl/vendor/qti/qvirt/BnVirtualizationService.h>
#include<string>
#include "VirtualMachine.h"

#define UEVENT_MSG_LEN 2048
using aidl::vendor::qti::qvirt::VirtualMachine;

namespace aidl {
namespace vendor {
namespace qti {
namespace qvirt {

class VirtualizationService : public BnVirtualizationService {
    public:
        VirtualizationService(int argc, char **argv);
        ndk::ScopedAStatus getVm(const std::string& in_vmName,
                std::shared_ptr<IVirtualMachine>* iVirtualMachine) override;
        std::shared_ptr<VirtualMachine> getVm_Internal(string vmName);
        int parseVMConfigFile();

    private:
        std::map<string,VirtualMachine::VmParameters> vmParameters_map;

        //Map of VM name to VirtualMachineObject
        std::map<std::string,std::shared_ptr<VirtualMachine> > vmObject_map;
};

static bool verbose = false;
//mutex to synchronize vmObject_map operations (insert into map, find and read from map).
inline std::mutex mMutex_;
static int uevent_fd = -1;
struct uevent {
    const char *EVENT;
    const char *vm_name;
};

}
}
}
}
