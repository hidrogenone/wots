// xmem.dll's physical pages through the registered shims, as a title calls them: XMemAllocatePhysicalPages,
// XMemFreePhysicalPages, XMemMapPhysicalPages, XMemMapPhysicalPagesScatter, the 64 KiB-page reserve-only
// XMemVirtualAlloc they are mapped into and the title's VirtualFree that releases it. The call shapes are the ones in
// xmem_physical.cpp's header comment; everything here is synthetic.
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "shims.h"

namespace {

using XMemVirtualAllocFn = void*(WINAPI*)(void*, SIZE_T, DWORD, ULONGLONG, DWORD);
using AllocatePhysicalFn = BOOL(WINAPI*)(ULONG64, ULONG_PTR*, ULONG_PTR*);
using FreePhysicalFn = BOOL(WINAPI*)(ULONG_PTR, ULONG_PTR*);
using MapPhysicalFn = PVOID(WINAPI*)(PVOID, ULONG_PTR, ULONG_PTR*);
using MapScatterFn = BOOL(WINAPI*)(PVOID*, ULONG_PTR, ULONG_PTR*);
using VirtualFreeFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);

constexpr SIZE_T kPage = 0x10000;
constexpr DWORD kPhysicalReserve = MEM_RESERVE | 0x20400000;  // MEM_LARGE_PAGES | MEM_PHYSICAL: 64 KiB pages
constexpr DWORD kGraphicsNoAccess = 0x800;
constexpr DWORD kGraphicsReadWrite = 0x2000;

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const char* what) {
    ++g_checks;
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", what);
    if (!condition) ++g_failures;
}

struct Api {
    XMemVirtualAllocFn virtual_alloc;
    AllocatePhysicalFn allocate;
    FreePhysicalFn free_pages;
    MapPhysicalFn map;
    MapScatterFn scatter;
    VirtualFreeFn virtual_free;
};

uint8_t* at(void* base, size_t page) { return static_cast<uint8_t*>(base) + page * kPage; }

MEMORY_BASIC_INFORMATION query(const void* p) {
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(p, &mbi, sizeof(mbi));
    return mbi;
}

bool committed(const void* p) { return query(p).State == MEM_COMMIT; }

void fill(uint8_t* p, uint8_t value) { std::memset(p, value, kPage); }

bool all_equal(const uint8_t* p, uint8_t value) {
    return std::all_of(p, p + kPage, [value](uint8_t b) { return b == value; });
}

void test_allocate(const Api& x) {
    ULONG_PTR count = 4;
    ULONG_PTR frames[4] = {};
    check(x.allocate(0x280, &count, frames) == TRUE, "XMemAllocatePhysicalPages(0x280, 4) returns TRUE");
    check(count == 4, "the page count comes back unchanged");
    bool shape = true;
    for (const ULONG_PTR f : frames) shape &= f != 0 && f % 16 == 0 && (f & ~0x1FFFFF0ull) == 0;
    check(shape, "every frame number is a nonzero multiple of 16 inside 25 bits");
    std::vector<ULONG_PTR> sorted(frames, frames + 4);
    std::sort(sorted.begin(), sorted.end());
    check(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end(), "the four frame numbers differ");

    ULONG_PTR none = 0;
    check(x.allocate(0x180, &none, nullptr) == TRUE && none == 0, "a count of 0 succeeds with no array");
    check(x.allocate(0x280, nullptr, frames) == FALSE && GetLastError() == ERROR_INVALID_PARAMETER,
          "a null count is ERROR_INVALID_PARAMETER");
    check(x.free_pages(4, frames) == TRUE, "XMemFreePhysicalPages frees them");
    check(x.free_pages(4, frames) == FALSE && GetLastError() == ERROR_INVALID_PARAMETER,
          "freeing them a second time is ERROR_INVALID_PARAMETER");
}

void test_map(const Api& x) {
    void* rw = x.virtual_alloc(nullptr, 16 * kPage, kPhysicalReserve, 0x21, PAGE_READWRITE);
    void* alias = x.virtual_alloc(nullptr, 16 * kPage, kPhysicalReserve, 0x23, PAGE_READWRITE | kGraphicsReadWrite);
    void* gpu_only = x.virtual_alloc(nullptr, 16 * kPage, kPhysicalReserve, 0x3, PAGE_NOACCESS | kGraphicsNoAccess);
    check(rw && alias && gpu_only, "three 64 KiB-page physical reservations (attributes 0x21, 0x23, 0x3)");
    if (!rw || !alias || !gpu_only) return;
    check(reinterpret_cast<uintptr_t>(rw) % kPage == 0, "a physical reservation is 64 KiB aligned");
    check(!committed(rw), "nothing is accessible in a reservation before a page is mapped");

    ULONG_PTR count = 4;
    ULONG_PTR frames[4] = {};
    check(x.allocate(0x380, &count, frames) == TRUE, "allocate four pages");

    check(x.map(rw, 4, frames) == rw, "XMemMapPhysicalPages returns the address it mapped at");
    bool rw_ok = true;
    for (size_t i = 0; i < 4; ++i) rw_ok &= committed(at(rw, i)) && query(at(rw, i)).Protect == PAGE_READWRITE;
    check(rw_ok, "the four mapped pages are read-write");
    check(all_equal(at(rw, 0), 0) && all_equal(at(rw, 3), 0), "new pages read as zero");
    for (size_t i = 0; i < 4; ++i) fill(at(rw, i), static_cast<uint8_t>(0x10 + i));
    check(!committed(at(rw, 4)), "the page after the mapped range stays unmapped");

    // The same pages at a second address, in another order: both views see one set of bytes.
    ULONG_PTR reversed[4] = {frames[3], frames[2], frames[1], frames[0]};
    check(x.map(at(alias, 8), 4, reversed) == at(alias, 8), "the same pages map at a second address");
    check(all_equal(at(alias, 8), 0x13) && all_equal(at(alias, 11), 0x10), "the second view reads the first's bytes");
    fill(at(alias, 9), 0x77);
    check(all_equal(at(rw, 2), 0x77), "a write through the second view shows in the first");

    check(x.map(gpu_only, 1, frames) == gpu_only, "a page maps into the PAGE_NOACCESS reservation");
    check(committed(gpu_only) && query(gpu_only).Protect == PAGE_NOACCESS,
          "there it keeps the CPU protection, PAGE_NOACCESS (the graphics bit is dropped)");

    // A bad frame number leaves the range as it was.
    ULONG_PTR bad[2] = {frames[0], 17};
    check(x.map(at(rw, 0), 2, bad) == nullptr && GetLastError() == ERROR_INVALID_PARAMETER,
          "a frame number that was never handed out is ERROR_INVALID_PARAMETER");
    check(all_equal(at(rw, 1), 0x11), "and the mapping it would have replaced is untouched");
    check(x.map(at(rw, 14), 4, frames) == nullptr, "a range past the reservation's end fails");
    static uint8_t not_reserved[2 * kPage];
    void* outside = reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(not_reserved) + kPage - 1) & ~(kPage - 1));
    check(x.map(outside, 1, frames) == nullptr, "an address outside every physical reservation fails");
    check(x.map(at(rw, 0) + 0x1000, 1, frames) == nullptr, "an address that is not 64 KiB aligned fails");

    // Remapping a page replaces what was there.
    check(x.map(at(rw, 0), 1, &frames[3]) == at(rw, 0) && all_equal(at(rw, 0), 0x13),
          "mapping another page over a mapped one replaces it");

    check(x.map(at(rw, 0), 4, nullptr) == at(rw, 0), "a null page array unmaps the range");
    check(!committed(at(rw, 0)) && !committed(at(rw, 3)), "the unmapped pages are inaccessible again");
    check(all_equal(at(alias, 11), 0x10), "unmapping one view leaves the other");
    check(x.map(at(rw, 0), 1, &frames[0]) == at(rw, 0) && all_equal(at(rw, 0), 0x10),
          "a page maps again where it was unmapped");

    // Scatter: listed addresses, 0 entries unmap.
    void* vas[3] = {at(rw, 5), at(rw, 12), at(rw, 0)};
    ULONG_PTR scatter_frames[3] = {frames[1], frames[2], 0};
    check(x.scatter(vas, 3, scatter_frames) == TRUE, "XMemMapPhysicalPagesScatter returns TRUE");
    check(all_equal(at(rw, 5), 0x11) && all_equal(at(rw, 12), 0x77), "it maps each page at its own address");
    check(!committed(at(rw, 0)), "a 0 entry unmaps its address");
    check(x.scatter(vas, 2, nullptr) == TRUE && !committed(at(rw, 5)) && !committed(at(rw, 12)),
          "a null page array unmaps every listed address");

    // Freeing a page unmaps it wherever it is, and it comes back zeroed.
    check(x.free_pages(4, frames) == TRUE, "free the four pages while they are mapped");
    check(!committed(at(alias, 8)) && !committed(at(alias, 11)) && !committed(gpu_only),
          "freeing unmaps the pages in every reservation");
    ULONG_PTR again_count = 4;
    ULONG_PTR again[4] = {};
    check(x.allocate(0x280, &again_count, again) == TRUE, "allocate four pages again");
    check(x.map(rw, 4, again) == rw, "map them");
    bool zero = true;
    for (size_t i = 0; i < 4; ++i) zero &= all_equal(at(rw, i), 0);
    check(zero, "reused pages read as zero");

    ULONG_PTR twice[2] = {again[0], again[0]};
    check(x.free_pages(2, twice) == FALSE && GetLastError() == ERROR_INVALID_PARAMETER,
          "freeing one frame number twice in one call is refused");
    check(committed(rw), "and frees nothing");

    check(x.virtual_free(at(rw, 1), 0, MEM_RELEASE) == FALSE, "VirtualFree inside a physical reservation fails");
    check(x.virtual_free(rw, 0, MEM_RELEASE) == TRUE, "VirtualFree(base, 0, MEM_RELEASE) releases it");
    check(query(rw).State == MEM_FREE && query(at(rw, 7)).State == MEM_FREE && query(at(rw, 15)).State == MEM_FREE,
          "the whole range is free afterwards, views and split placeholders included");
    check(x.map(rw, 1, again) == nullptr, "nothing maps into a released reservation");
    check(x.free_pages(4, again) == TRUE, "the pages that were mapped there can still be freed");
    check(x.virtual_free(alias, 0, MEM_RELEASE) == TRUE && x.virtual_free(gpu_only, 0, MEM_RELEASE) == TRUE,
          "release the other two");

    // Plain memory still goes to the host.
    void* plain = VirtualAlloc(nullptr, kPage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    check(plain && x.virtual_free(plain, 0, MEM_RELEASE) == TRUE && query(plain).State == MEM_FREE,
          "VirtualFree of ordinary memory is the host's");
}

// The startup reservations are 24 GiB; the page tables of a reservation that size must not cost more than a few MB,
// and a page at its far end maps like any other.
void test_large_reservation(const Api& x) {
    constexpr SIZE_T size = 24ull << 30;
    void* big = x.virtual_alloc(nullptr, size, kPhysicalReserve, 0x21, PAGE_READWRITE);
    check(big != nullptr, "a 24 GiB physical reservation");
    if (!big) return;
    ULONG_PTR count = 1;
    ULONG_PTR frame = 0;
    check(x.allocate(0x280, &count, &frame) == TRUE, "allocate one page");
    uint8_t* last = static_cast<uint8_t*>(big) + size - kPage;
    check(x.map(last, 1, &frame) == last, "it maps at the last page of the reservation");
    last[kPage - 1] = 0x5a;
    check(last[kPage - 1] == 0x5a, "and is writable there");
    check(x.free_pages(1, &frame) == TRUE && x.virtual_free(big, 0, MEM_RELEASE) == TRUE, "free and release");
}

// Many pages at once, as the startup pools ask for (a few hundred MB each).
void test_bulk(const Api& x) {
    constexpr ULONG_PTR pages = 2048;  // 128 MiB, four sections
    void* region = x.virtual_alloc(nullptr, pages * kPage, kPhysicalReserve, 0x23, PAGE_READWRITE | kGraphicsReadWrite);
    std::vector<ULONG_PTR> frames(pages);
    ULONG_PTR count = pages;
    check(region && x.allocate(0x280, &count, frames.data()) == TRUE && count == pages, "allocate 2048 pages");
    if (!region || count != pages) return;
    check(x.map(region, pages, frames.data()) == region, "map 128 MiB in one call");
    bool ok = true;
    for (ULONG_PTR i = 0; i < pages; ++i) at(region, i)[0] = static_cast<uint8_t>(i);
    for (ULONG_PTR i = 0; i < pages; ++i) ok &= at(region, i)[0] == static_cast<uint8_t>(i);
    check(ok, "every page holds its own byte");
    check(x.free_pages(pages, frames.data()) == TRUE && x.virtual_free(region, 0, MEM_RELEASE) == TRUE,
          "free and release");
}

}  // namespace

int main() {
    std::printf("xmem_physical_test: xmem.dll physical pages\n");
    Api x{};
    x.virtual_alloc = reinterpret_cast<XMemVirtualAllocFn>(rt::shims::find("xmem.dll", "XMemVirtualAlloc"));
    x.allocate = reinterpret_cast<AllocatePhysicalFn>(rt::shims::find("xmem.dll", "XMemAllocatePhysicalPages"));
    x.free_pages = reinterpret_cast<FreePhysicalFn>(rt::shims::find("xmem.dll", "XMemFreePhysicalPages"));
    x.map = reinterpret_cast<MapPhysicalFn>(rt::shims::find("xmem.dll", "XMemMapPhysicalPages"));
    x.scatter = reinterpret_cast<MapScatterFn>(rt::shims::find("xmem.dll", "XMemMapPhysicalPagesScatter"));
    x.virtual_free = reinterpret_cast<VirtualFreeFn>(rt::shims::find("api-ms-win-core-memory-l1-1-0.dll", "VirtualFree"));
    check(x.virtual_alloc && x.allocate && x.free_pages && x.map && x.scatter && x.virtual_free,
          "the registry serves the four physical-page exports, XMemVirtualAlloc and the title's VirtualFree");
    check(rt::shims::find("kernel32.dll", "VirtualFree") == reinterpret_cast<void*>(x.virtual_free),
          "kernel32.dll!VirtualFree is the same shim");
    if (x.virtual_alloc && x.allocate && x.free_pages && x.map && x.scatter && x.virtual_free) {
        test_allocate(x);
        test_map(x);
        test_large_reservation(x);
        test_bulk(x);
    }
    std::printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
