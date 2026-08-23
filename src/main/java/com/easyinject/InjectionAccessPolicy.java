package com.easyinject;

/**
 * Compile-time-selected process access policy for DLL injection.
 */
final class InjectionAccessPolicy {
    private InjectionAccessPolicy() {
    }

    static int requiredProcessAccess() {
        // <compatibility-policy>
        // Preserve the historical access mask in the compatibility artifact.
        return 0x1F0FFF;
        // </compatibility-policy>
        // <reduced-policy>
//|        return WindowsNative.PROCESS_CREATE_THREAD
//|            | WindowsNative.PROCESS_QUERY_INFORMATION
//|            | WindowsNative.PROCESS_VM_OPERATION
//|            | WindowsNative.PROCESS_VM_WRITE
//|            | WindowsNative.PROCESS_VM_READ;
        // </reduced-policy>
    }
}
