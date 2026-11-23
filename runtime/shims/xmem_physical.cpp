// xmem.dll's physical pages: XMemAllocatePhysicalPages, XMemFreePhysicalPages, XMemMapPhysicalPages and
// XMemMapPhysicalPagesScatter, and the reservations they are mapped into.
//
// The shapes come from the retail executable's call sites (1.0.2.1; four callers of the allocation, three of the free,
// eleven of the map and two of the scatter form). They follow the Win32 AWE functions with the process handle left
// out and an attribute word added:
//   BOOL  XMemAllocatePhysicalPages(ULONG64 attributes, ULONG_PTR* count, ULONG_PTR* page_array)
//           count is in/out, in 64 KiB pages; the callers require TRUE and the count written back unchanged.
//           Measured attribute words: 0x180, 0x280, 0x380 (not decoded; recorded in the startup trace).
//   BOOL  XMemFreePhysicalPages(ULONG_PTR count, ULONG_PTR* page_array)        count by value
//   PVOID XMemMapPhysicalPages(PVOID va, ULONG_PTR count, ULONG_PTR* page_array)
//           the callers test the full 64-bit result for non-null; a null page_array unmaps the range.
//   BOOL  XMemMapPhysicalPagesScatter(PVOID* va_array, ULONG_PTR count, ULONG_PTR* page_array)
//           a null page_array unmaps every listed page; a caller writes 0 entries for pages it leaves unmapped.
// The pages are mapped into ranges reserved with XMemVirtualAlloc(nullptr, size, MEM_RESERVE | MEM_LARGE_PAGES |
// MEM_PHYSICAL, attributes, protect), MEM_LARGE_PAGES | MEM_PHYSICAL being the console's 64 KiB page mode; the
// executable makes two 24 GiB ones at startup and smaller ones per pool. It frees them with VirtualFree.
//
// The page-array entries are frame numbers the title treats as opaque, except that one caller rebuilds an entry as a
// 64 KiB page index times 16, masked to 25 bits. So an entry here is a 4 KiB frame number of a 64 KiB page: (slot + 1)
// * 16, never 0 (0 means "unmapped" in the scatter form), and the store has at most 2^21 - 1 slots (128 GiB).
//
// The host has no user-mode physical pages without SeLockMemoryPrivilege (AWE), and AWE pages cannot be mapped at two
// addresses at once, which the console allows (the two 24 GiB reservations differ only in their attribute word and
// CPU protection). So a page is a 64 KiB slot of a pagefile-backed section (sections of 512 slots), and a mapping is a
// view of that slot: the reservation is a placeholder (VirtualAlloc2 with MEM_RESERVE_PLACEHOLDER), a page is split
// out of it and replaced with a view (MapViewOfFile3 with MEM_REPLACE_PLACEHOLDER), and unmapping puts the
// placeholder back (UnmapViewOfFile2 with MEM_PRESERVE_PLACEHOLDER). One page can then sit at any number of addresses
// and every view sees the same bytes, as on the console. New pages read as zero, a freed page is zeroed before it is
// handed out again, and freeing a page unmaps it everywhere (as FreeUserPhysicalPages does).
//
// Not done: the GPU side. These pages are CPU memory only; the D3D12 layer does not see them yet. #5381's
// PhysicalPageStore is the same mechanism with a device-local half and dirty tracking, and can take this store's
// sections. Committing ordinary memory inside a physical reservation fails (ERROR_INVALID_ADDRESS), as on Win32.
#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <string>
#include <vector>

#include "shims.h"
#include "startup_trace.h"
#include "xmem_physical.h"

namespace {

constexpr SIZE_T kPage = 0x10000;
constexpr ULONG_PTR kFramesPerPage = kPage / 0x1000;
constexpr uint32_t kChunkPages = 512;
constexpr uint32_t kMaxSlots = (1u << 21) - 1;

using VirtualAlloc2Fn = PVOID(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
using MapViewOfFile3Fn = PVOID(WINAPI*)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*,
                                        ULONG);
using UnmapViewOfFile2Fn = BOOL(WINAPI*)(HANDLE, PVOID, ULONG);

// Looked up rather than imported, so the runtime still starts where they are missing (before Windows 10 1803, or a
// Wine without placeholders); physical reservations are then ordinary ones and nothing can be mapped into them.
struct PlaceholderApi {
    VirtualAlloc2Fn alloc2 = nullptr;
    MapViewOfFile3Fn map3 = nullptr;
    UnmapViewOfFile2Fn unmap2 = nullptr;
    bool ok() const { return alloc2 && map3 && unmap2; }
};

const PlaceholderApi& api() {
    static const PlaceholderApi a = [] {
        PlaceholderApi r;
        if (HMODULE k = GetModuleHandleW(L"kernelbase.dll")) {
            r.alloc2 = reinterpret_cast<VirtualAlloc2Fn>(reinterpret_cast<void*>(GetProcAddress(k, "VirtualAlloc2")));
            r.map3 = reinterpret_cast<MapViewOfFile3Fn>(reinterpret_cast<void*>(GetProcAddress(k, "MapViewOfFile3")));
            r.unmap2 =
                reinterpret_cast<UnmapViewOfFile2Fn>(reinterpret_cast<void*>(GetProcAddress(k, "UnmapViewOfFile2")));
        }
        return r;
    }();
    return a;
}

struct Chunk {
    HANDLE section;
    uint8_t* view;  // the store's own view of the whole section, for zeroing a reused page
};

struct Slot {
    bool allocated = false;
    bool needs_zero = false;
    std::vector<uintptr_t> mapped_at;
};

struct Region {
    SIZE_T pages = 0;
    DWORD protect = PAGE_NOACCESS;
    std::vector<uint32_t> page;     // slot + 1 mapped at each page, 0 for none
    std::vector<uint8_t> isolated;  // the page is a placeholder or view of its own
};

std::mutex g_mutex;
std::vector<Chunk> g_chunks;
std::vector<Slot> g_slots;
std::vector<uint32_t> g_free;            // free slots, the next one at the back
std::map<uintptr_t, Region> g_regions;  // physical reservations by base

ULONG_PTR frame_of(uint32_t slot) { return (static_cast<ULONG_PTR>(slot) + 1) * kFramesPerPage; }

bool slot_of(ULONG_PTR frame, uint32_t& slot) {
    if (frame == 0 || frame % kFramesPerPage != 0) return false;
    const ULONG_PTR index = frame / kFramesPerPage - 1;
    if (index >= g_slots.size() || !g_slots[index].allocated) return false;
    slot = static_cast<uint32_t>(index);
    return true;
}

// Adds sections until `count` slots are free.
bool grow(size_t count) {
    while (g_free.size() < count) {
        if (g_slots.size() + kChunkPages > kMaxSlots) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }
        constexpr uint64_t bytes = static_cast<uint64_t>(kChunkPages) * kPage;
        HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_COMMIT,
                                            static_cast<DWORD>(bytes >> 32), static_cast<DWORD>(bytes), nullptr);
        if (!section) return false;
        void* view = MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            const DWORD error = GetLastError();
            CloseHandle(section);
            SetLastError(error);
            return false;
        }
        const uint32_t first = static_cast<uint32_t>(g_slots.size());
        g_chunks.push_back({section, static_cast<uint8_t*>(view)});
        g_slots.resize(first + kChunkPages);
        for (uint32_t i = kChunkPages; i-- > 0;) g_free.push_back(first + i);
    }
    return true;
}

Region* region_of(uintptr_t va, ULONG_PTR count, uintptr_t& base, size_t& index) {
    auto it = g_regions.upper_bound(va);
    if (it == g_regions.begin()) return nullptr;
    --it;
    base = it->first;
    Region& r = it->second;
    if ((va - base) / kPage >= r.pages) return nullptr;
    index = (va - base) / kPage;
    if (count > r.pages - index) return nullptr;
    return &r;
}

uintptr_t page_address(uintptr_t base, size_t index) { return base + index * kPage; }

// Splits page `index` out of the placeholder that holds it, unless it already is a placeholder of its own.
bool isolate(Region& r, uintptr_t base, size_t index) {
    if (r.isolated[index]) return true;
    const uintptr_t a = page_address(base, index);
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof(mbi))) return false;
    const uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) != a || end != a + kPage) {
        if (!VirtualFree(reinterpret_cast<void*>(a), kPage, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) return false;
    }
    r.isolated[index] = 1;
    return true;
}

void forget_mapping(uint32_t slot, uintptr_t a) {
    auto& at = g_slots[slot].mapped_at;
    at.erase(std::remove(at.begin(), at.end(), a), at.end());
}

bool unmap_page(Region& r, uintptr_t base, size_t index) {
    if (r.page[index] == 0) return true;
    const uintptr_t a = page_address(base, index);
    if (!api().unmap2(GetCurrentProcess(), reinterpret_cast<void*>(a), MEM_PRESERVE_PLACEHOLDER)) return false;
    forget_mapping(r.page[index] - 1, a);
    r.page[index] = 0;
    return true;
}

bool map_page(Region& r, uintptr_t base, size_t index, uint32_t slot) {
    if (r.page[index] == slot + 1) return true;
    if (!unmap_page(r, base, index) || !isolate(r, base, index)) return false;
    void* const a = reinterpret_cast<void*>(page_address(base, index));
    const Chunk& chunk = g_chunks[slot / kChunkPages];
    const ULONG64 offset = static_cast<ULONG64>(slot % kChunkPages) * kPage;
    void* view = api().map3(chunk.section, GetCurrentProcess(), a, offset, kPage, MEM_REPLACE_PLACEHOLDER, r.protect,
                            nullptr, 0);
    if (!view && r.protect != PAGE_READWRITE) {
        // A protection the view cannot be created with directly (PAGE_NOACCESS on some hosts): map it read-write and
        // narrow it. The placeholder is still in place after the failed call.
        view = api().map3(chunk.section, GetCurrentProcess(), a, offset, kPage, MEM_REPLACE_PLACEHOLDER,
                          PAGE_READWRITE, nullptr, 0);
        DWORD old = 0;
        if (view && !VirtualProtect(view, kPage, r.protect, &old)) {
            const DWORD error = GetLastError();
            api().unmap2(GetCurrentProcess(), view, MEM_PRESERVE_PLACEHOLDER);
            SetLastError(error);
            return false;
        }
    }
    if (!view) return false;
    g_slots[slot].mapped_at.push_back(page_address(base, index));
    r.page[index] = slot + 1;
    return true;
}

// Unmaps a slot wherever it is mapped.
bool unmap_everywhere(uint32_t slot) {
    while (!g_slots[slot].mapped_at.empty()) {
        const uintptr_t a = g_slots[slot].mapped_at.back();
        uintptr_t base = 0;
        size_t index = 0;
        Region* r = region_of(a, 1, base, index);
        if (!r || !unmap_page(*r, base, index)) {
            g_slots[slot].mapped_at.pop_back();  // never left behind as a dangling record
            return false;
        }
    }
    return true;
}

// The first allocation for each distinct attribute word, to the startup trace (gta6rt --trace).
void note_allocation(uint64_t attributes, ULONG_PTR count, const void* caller) {
    if (!rt::startup_trace::enabled()) return;
    static std::mutex mutex;
    static std::set<uint64_t> seen;
    {
        const std::lock_guard lock(mutex);
        if (!seen.insert(attributes).second) return;
    }
    rt::startup_trace::event(
        "xmem_physical",
        "\"api\":\"XMemAllocatePhysicalPages\",\"attributes\":" +
            rt::startup_trace::quote(rt::startup_trace::hex(attributes)) +
            ",\"pages\":" + std::to_string(static_cast<uint64_t>(count)) + ",\"caller\":" +
            rt::startup_trace::quote(rt::startup_trace::where(reinterpret_cast<uint64_t>(caller))));
}

BOOL WINAPI XMemAllocatePhysicalPages(ULONG64 attributes, ULONG_PTR* count, ULONG_PTR* page_array) {
    note_allocation(attributes, count ? *count : 0, _ReturnAddress());
    if (!count || (*count != 0 && !page_array)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const ULONG_PTR wanted = *count;
    try {
        const std::lock_guard lock(g_mutex);
        if (wanted > kMaxSlots || !grow(static_cast<size_t>(wanted))) {
            *count = 0;
            if (wanted > kMaxSlots) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        for (ULONG_PTR i = 0; i < wanted; ++i) {
            const uint32_t slot = g_free.back();
            g_free.pop_back();
            Slot& s = g_slots[slot];
            if (s.needs_zero) {
                std::memset(g_chunks[slot / kChunkPages].view + static_cast<size_t>(slot % kChunkPages) * kPage, 0,
                            kPage);
                s.needs_zero = false;
            }
            s.allocated = true;
            page_array[i] = frame_of(slot);
        }
        return TRUE;
    } catch (const std::bad_alloc&) {
        *count = 0;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

BOOL WINAPI XMemFreePhysicalPages(ULONG_PTR count, ULONG_PTR* page_array) {
    if (count != 0 && !page_array) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    try {
        const std::lock_guard lock(g_mutex);
        std::vector<uint32_t> slots(static_cast<size_t>(count));
        for (ULONG_PTR i = 0; i < count; ++i) {
            if (!slot_of(page_array[i], slots[i])) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        }
        std::vector<uint32_t> sorted = slots;
        std::sort(sorted.begin(), sorted.end());
        if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        g_free.reserve(g_free.size() + slots.size());
        BOOL ok = TRUE;
        for (const uint32_t slot : slots) {
            if (!unmap_everywhere(slot)) ok = FALSE;
            Slot& s = g_slots[slot];
            s.allocated = false;
            s.needs_zero = true;
            g_free.push_back(slot);
        }
        return ok;
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

// Checks every entry before anything changes, so a bad frame number leaves the mappings as they were.
bool resolve_frames(ULONG_PTR count, const ULONG_PTR* page_array, std::vector<uint32_t>& slots) {
    slots.assign(static_cast<size_t>(count), 0);
    if (!page_array) return true;
    for (ULONG_PTR i = 0; i < count; ++i) {
        if (page_array[i] == 0) continue;
        uint32_t slot = 0;
        if (!slot_of(page_array[i], slot)) return false;
        slots[i] = slot + 1;
    }
    return true;
}

PVOID WINAPI XMemMapPhysicalPages(PVOID va, ULONG_PTR count, ULONG_PTR* page_array) {
    const uintptr_t a = reinterpret_cast<uintptr_t>(va);
    if (!api().ok()) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return nullptr;
    }
    if (!va || a % kPage != 0 || count == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    try {
        const std::lock_guard lock(g_mutex);
        uintptr_t base = 0;
        size_t first = 0;
        Region* r = region_of(a, count, base, first);
        std::vector<uint32_t> slots;
        if (!r || !resolve_frames(count, page_array, slots)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return nullptr;
        }
        for (ULONG_PTR i = 0; i < count; ++i) {
            const bool ok = slots[i] ? map_page(*r, base, first + i, slots[i] - 1) : unmap_page(*r, base, first + i);
            if (!ok) return nullptr;
        }
        return va;
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
}

BOOL WINAPI XMemMapPhysicalPagesScatter(PVOID* va_array, ULONG_PTR count, ULONG_PTR* page_array) {
    if (!api().ok()) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (count != 0 && !va_array) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    try {
        const std::lock_guard lock(g_mutex);
        std::vector<uint32_t> slots;
        if (!resolve_frames(count, page_array, slots)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        struct Target {
            Region* region;
            uintptr_t base;
            size_t index;
        };
        std::vector<Target> targets(static_cast<size_t>(count));
        for (ULONG_PTR i = 0; i < count; ++i) {
            const uintptr_t a = reinterpret_cast<uintptr_t>(va_array[i]);
            Target& t = targets[i];
            t.region = a % kPage == 0 ? region_of(a, 1, t.base, t.index) : nullptr;
            if (!t.region) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        }
        for (ULONG_PTR i = 0; i < count; ++i) {
            const Target& t = targets[i];
            const bool ok =
                slots[i] ? map_page(*t.region, t.base, t.index, slots[i] - 1) : unmap_page(*t.region, t.base, t.index);
            if (!ok) return FALSE;
        }
        return TRUE;
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

void* reserve_physical(SIZE_T size, DWORD protect) {
    if (!api().ok()) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true)) {
            std::fprintf(stderr,
                         "[rt] xmem: no VirtualAlloc2/MapViewOfFile3 placeholders on this host; physical-page "
                         "reservations are ordinary ones and XMemMapPhysicalPages fails\n");
        }
        return VirtualAlloc(nullptr, size, MEM_RESERVE, protect);
    }
    if (size == 0 || size > (std::numeric_limits<SIZE_T>::max)() - (kPage - 1)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    size = (size + kPage - 1) & ~(kPage - 1);
    void* p = api().alloc2(GetCurrentProcess(), nullptr, size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                           nullptr, 0);
    if (!p) return nullptr;
    try {
        const std::lock_guard lock(g_mutex);
        Region r;
        r.pages = size / kPage;
        r.protect = protect;
        r.page.assign(r.pages, 0);
        r.isolated.assign(r.pages, 0);
        g_regions.emplace(reinterpret_cast<uintptr_t>(p), std::move(r));
    } catch (const std::bad_alloc&) {
        VirtualFree(p, 0, MEM_RELEASE);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    return p;
}

// Unmaps every page of a physical reservation and releases its placeholders. Called with g_mutex held.
bool release_region(std::map<uintptr_t, Region>::iterator it) {
    const uintptr_t base = it->first;
    Region& r = it->second;
    bool ok = true;
    for (size_t i = 0; i < r.pages; ++i) {
        if (!unmap_page(r, base, i)) ok = false;
    }
    const uintptr_t end = page_address(base, r.pages);
    for (uintptr_t a = base; a < end;) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof(mbi))) return false;
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (!VirtualFree(reinterpret_cast<void*>(a), 0, MEM_RELEASE)) ok = false;
        a = next > a ? next : a + kPage;
    }
    g_regions.erase(it);
    return ok;
}

// kernel32!VirtualFree as a title calls it: a physical reservation is a set of placeholders and views, which the
// host's VirtualFree(base, 0, MEM_RELEASE) would release only the first of. Everything else goes to the host.
BOOL WINAPI TitleVirtualFree(LPVOID address, SIZE_T size, DWORD free_type) {
    const uintptr_t a = reinterpret_cast<uintptr_t>(address);
    {
        const std::lock_guard lock(g_mutex);
        auto it = g_regions.upper_bound(a);
        if (it != g_regions.begin()) {
            --it;
            if (a - it->first < it->second.pages * kPage) {
                if (a == it->first && size == 0 && free_type == MEM_RELEASE) {
                    if (release_region(it)) return TRUE;
                    return FALSE;
                }
                // Decommitting or releasing part of a physical reservation fails on Win32 as well.
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        }
    }
    return VirtualFree(address, size, free_type);
}

const bool g_registered = (rt::xmem::set_physical_reserve(&reserve_physical), true);

}  // namespace

#define TITLE_VIRTUAL_FREE(dll) {dll, "VirtualFree", reinterpret_cast<void*>(&TitleVirtualFree)}

SHIM_TABLE(xmem_physical,
    {"xmem.dll", "XMemAllocatePhysicalPages", reinterpret_cast<void*>(&XMemAllocatePhysicalPages)},
    {"xmem.dll", "XMemFreePhysicalPages", reinterpret_cast<void*>(&XMemFreePhysicalPages)},
    {"xmem.dll", "XMemMapPhysicalPages", reinterpret_cast<void*>(&XMemMapPhysicalPages)},
    {"xmem.dll", "XMemMapPhysicalPagesScatter", reinterpret_cast<void*>(&XMemMapPhysicalPagesScatter)},
    TITLE_VIRTUAL_FREE("kernel32.dll"),
    TITLE_VIRTUAL_FREE("kernelbase.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-0.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-1.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-2.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-3.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-4.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-5.dll"),
    TITLE_VIRTUAL_FREE("api-ms-win-core-memory-l1-1-6.dll"),
);
