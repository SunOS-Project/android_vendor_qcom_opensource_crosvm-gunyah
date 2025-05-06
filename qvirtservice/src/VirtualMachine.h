/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include<aidl/vendor/qti/qvirt/BnVirtualMachine.h>
#include<unordered_map>
#include<string>
#include<vector>
#include<map>
#include <log/log.h>

#define VENDOR_CONFIG_FILE "/vendor/etc/qvirtmgr-vndr.json"
#define VM_BINARY_FILE     "/system_ext/bin/qcrosvm"
#define DEFAULT_BOOT_COMPLETE_TIMEOUT     60
#define BUFFER_MAX            1024
#define VM_DISK_ARGUMENT   "--disk=%s,label=%s,rw=%s"              // Disk input parameter format
#define VM_NAME_ARGUMENT   "--vm=%s"
#define VM_STATUS_PROPERTY "vendor.qvirtmgr.%s.status"             // vm name input parameter format

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "qvirtservice"

using namespace std;
using aidl::vendor::qti::qvirt::VirtualMachineState;
using aidl::vendor::qti::qvirt::IVirtualMachineCallback;

namespace aidl {
namespace vendor {
namespace qti {
namespace qvirt {
class VirtualMachine : public BnVirtualMachine {
    public:
        ndk::ScopedAStatus registerCallback(
                const std::shared_ptr<IVirtualMachineCallback>& in_callback) override;
        ndk::ScopedAStatus getState(VirtualMachineState* virtualMachineState) override;
        ndk::ScopedAStatus start() override;

        typedef enum {
            INVALID = -1,
            CREATE = 0,
            START = 1,
            STOP = 2,
            RESTART = 3,
            PANIC = 4,
            NOT_SUPPORTED = 5,
        } ControlState;

        static inline ControlState getControlState(const string &state) {
           if (state == "create")   return ControlState::CREATE;
           if (state == "start")    return ControlState::START;
           if (state == "stop")     return ControlState::STOP;
           if (state == "restart")  return ControlState::RESTART;
           if (state == "panic")    return ControlState::PANIC;

           return ControlState::INVALID;
        }

        static inline std::string getStatetoStr(VirtualMachineState val) {
            switch(val) {
            case VirtualMachineState::NOT_STARTED:
              return "NOT_STARTED";
            case VirtualMachineState::RUNNING:
              return "RUNNING";
            case VirtualMachineState::STOPPED:
              return "STOPPED";
            default:
              return std::to_string(static_cast<int32_t>(val));
            }
        }

        struct DiskProperties {
            string image_;
            string label_;
            bool readWrite_;

            DiskProperties(string image, string label, bool readWrite = true) : image_(image),
                    label_(label), readWrite_(readWrite){}
        };

        // Data structure to contain individual vm(s) meta data
        struct VmParameters {
            string vmName_;
            string vmBinary_;
            bool isEnabled_;
            ControlState bootOperation_;
            vector<DiskProperties> disk_;
            int pid_;
            unsigned char bootTryCount_;
            unsigned char bootWaitTime_;
            unsigned int bootCompleteTimeout_;
            bool noFSDependency_;
            bool autostart;
            bool on_demand_start_supported;
            VmParameters() {
                vmBinary_ = string("");
                bootOperation_ = ControlState::NOT_SUPPORTED;
                pid_ = -1;
                bootTryCount_ = 0;
                bootWaitTime_ = 0;
                bootCompleteTimeout_ = DEFAULT_BOOT_COMPLETE_TIMEOUT;
                noFSDependency_ = false;
                autostart = false;
                on_demand_start_supported = false;
            }
            VmParameters(string vmName, bool isEnabled): vmName_(vmName),isEnabled_(isEnabled) {
                vmBinary_ = string("");
                bootOperation_ = ControlState::NOT_SUPPORTED;
                pid_ = -1;
                bootTryCount_ = 0;
                bootWaitTime_ = 0;
                bootCompleteTimeout_ = DEFAULT_BOOT_COMPLETE_TIMEOUT;
                noFSDependency_ = false;
                autostart = false;
                on_demand_start_supported = false;
            }
        };

        //Data structure to represent entire VirtualMachine data.
        struct VmInstance {
          string vmName_;
          std::vector<std::shared_ptr<IVirtualMachineCallback>> virtualMachineCallbacks_;
          VirtualMachineState vmstate_;
          VmParameters vmParameters_;
          VmInstance() {
              vmstate_ = {VirtualMachineState::NOT_STARTED};
          }
        };

        void notify_clients(VirtualMachineState vmState);
        void notify_clients_locked(string EVENT);
        void launch_autostartVMs();
        int launchVM(string &response);
        int bootVM(int &pid,string &response);
        unsigned char bootSequence(string &response);
        void setVmStatusProperty(string vmStatus);

        VmInstance vmInstance;

        // OnBinderDiedContext is a type used as a cookie passed deathRecipient.
        // The deathRecipient's onBinderDied function takes only a cookie as input and we have to
        // store all the contexts as the cookie.
        struct OnBinderDiedContext {
            VirtualMachine* server;
            const AIBinder* clientId;
            pid_t pid;
            uid_t uid;
        };
        static void onBinderDied(void* cookie);
        void handleBinderDeath(OnBinderDiedContext* context);

        bool verbose = false;
        #define VM_LOGV(...)          { if (verbose) ALOGI(__VA_ARGS__); }
        #define VM_LOGI(...)          { ALOGI(__VA_ARGS__); }
        #define VM_LOGE(...)          { ALOGE(__VA_ARGS__); }

    private:
        //Mutex per VirtualMachineObject to synchronize individual Vm's data (vmInstance) and api's.
        mutable std::mutex vmMutex;
        // A map of callback ptr to context that is required for handleBinderDeath.
        std::unordered_map<const AIBinder*, std::unique_ptr<OnBinderDiedContext>>
                mOnBinderDiedContexts;
        bool autostart_done = false;
};
}
}
}
}
