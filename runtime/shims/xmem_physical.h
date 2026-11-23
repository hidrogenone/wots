// The seam between xmem.cpp's XMemVirtualAlloc and the physical-page store in xmem_physical.cpp.
//
// xmem.cpp is compiled into many test targets that do not link xmem_physical.cpp, so it does not call into it
// directly: xmem_physical.cpp registers its reservation function here at static initialisation, and XMemVirtualAlloc
// uses it when it is set. Without it (a target that does not link the store), the reservation is an ordinary one.
#pragma once
#include <windows.h>

namespace rt::xmem {

// Reserves `size` bytes (a multiple of 64 KiB) of address space that XMemMapPhysicalPages[Scatter] can map pages
// into, with `protect` as the CPU protection of every page mapped there. Null with the last error set on failure.
using PhysicalReserveFn = void* (*)(SIZE_T size, DWORD protect);

void set_physical_reserve(PhysicalReserveFn fn);
PhysicalReserveFn physical_reserve();

}  // namespace rt::xmem
