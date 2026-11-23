// Null-PSO Draw/Dispatch are legal recording no-ops and must not poison a list's Close().
// Compare directly against native Windows D3D12 WARP. Synthetic only, no game data.
#include "vk_test_device.h"
#include "host_wine.h"
#include "../shims/d3d12_com.h"
#include <dxgi1_4.h>
#include <cstdio>
#include <iterator>

namespace {
template <class T>
struct Ref {
    T* p = nullptr;
    ~Ref() {
        if (p) p->Release();
    }
    T* operator->() const { return p; }
};

enum class Call { draw, indexed, dispatch };
struct Case {
    const char* name;
    Call call;
    bool zero;
    bool bundle;
};

void record(ID3D12GraphicsCommandList* list, const Case& test) {
    switch (test.call) {
    case Call::draw:
        list->DrawInstanced(test.zero ? 0 : 3, 1, 0, 0);
        break;
    case Call::indexed:
        list->DrawIndexedInstanced(test.zero ? 0 : 3, 1, 0, 0, 0);
        break;
    case Call::dispatch:
        list->Dispatch(test.zero ? 0 : 1, 1, 1);
        break;
    }
}

HRESULT close_case(ID3D12Device* dev, const Case& test) {
    const D3D12_COMMAND_LIST_TYPE type =
        test.bundle ? D3D12_COMMAND_LIST_TYPE_BUNDLE : D3D12_COMMAND_LIST_TYPE_DIRECT;
    Ref<ID3D12CommandAllocator> allocator;
    HRESULT hr = dev->CreateCommandAllocator(type, IID_PPV_ARGS(&allocator.p));
    if (FAILED(hr)) return hr;
    Ref<ID3D12GraphicsCommandList> list;
    hr = dev->CreateCommandList(0, type, allocator.p, nullptr, IID_PPV_ARGS(&list.p));
    if (FAILED(hr)) return hr;
    record(list.p, test);
    return list->Close();
}

HRESULT indirect_dispatch_close(ID3D12Device* dev) {
    D3D12_INDIRECT_ARGUMENT_DESC arg{};
    arg.Type = D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH;
    D3D12_COMMAND_SIGNATURE_DESC sig_desc{sizeof(D3D12_DISPATCH_ARGUMENTS), 1, &arg, 0};
    Ref<ID3D12CommandSignature> sig;
    HRESULT hr = dev->CreateCommandSignature(&sig_desc, nullptr, IID_PPV_ARGS(&sig.p));
    if (FAILED(hr)) return hr;
    const D3D12_HEAP_PROPERTIES upload_heap{D3D12_HEAP_TYPE_UPLOAD};
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = 256;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    Ref<ID3D12Resource> args;
    hr = dev->CreateCommittedResource(&upload_heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_GENERIC_READ,
                                      nullptr, IID_PPV_ARGS(&args.p));
    if (FAILED(hr)) return hr;
    Ref<ID3D12CommandAllocator> allocator;
    hr = dev->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator.p));
    if (FAILED(hr)) return hr;
    Ref<ID3D12GraphicsCommandList> list;
    hr = dev->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator.p, nullptr, IID_PPV_ARGS(&list.p));
    if (FAILED(hr)) return hr;
    list->ExecuteIndirect(sig.p, 1, args.p, 0, nullptr, 0);
    return list->Close();
}

bool submit_copy_after_no_pso(ID3D12Device* dev, bool allow_nonzero) {
    constexpr unsigned bytes = 256;
    const D3D12_HEAP_PROPERTIES upload_heap{D3D12_HEAP_TYPE_UPLOAD};
    const D3D12_HEAP_PROPERTIES readback_heap{D3D12_HEAP_TYPE_READBACK};
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = bytes;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    Ref<ID3D12Resource> src, dst;
    if (FAILED(dev->CreateCommittedResource(&upload_heap, D3D12_HEAP_FLAG_NONE, &desc,
                                            D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, IID_PPV_ARGS(&src.p))) ||
        FAILED(dev->CreateCommittedResource(&readback_heap, D3D12_HEAP_FLAG_NONE, &desc,
                                            D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&dst.p))))
        return false;
    void* mapped = nullptr;
    if (FAILED(src->Map(0, nullptr, &mapped))) return false;
    for (unsigned i = 0; i < bytes; ++i)
        static_cast<unsigned char*>(mapped)[i] = static_cast<unsigned char>(i ^ 0xa5);
    src->Unmap(0, nullptr);

    D3D12_COMMAND_QUEUE_DESC queue_desc{};
    Ref<ID3D12CommandQueue> queue;
    Ref<ID3D12CommandAllocator> allocator;
    Ref<ID3D12GraphicsCommandList> list;
    Ref<ID3D12Fence> fence;
    if (FAILED(dev->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&queue.p))) ||
        FAILED(dev->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator.p))) ||
        FAILED(dev->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator.p, nullptr,
                                       IID_PPV_ARGS(&list.p))) ||
        FAILED(dev->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence.p))))
        return false;
    // Native WARP can accept a nonzero null-PSO draw at Close, but submitting it may remove the device;
    // exercise nonzero null-PSO calls on the layer only and zero-work calls on both backends.
    if (allow_nonzero) {
        D3D12_INDIRECT_ARGUMENT_DESC arg{};
        arg.Type = D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH;
        D3D12_COMMAND_SIGNATURE_DESC sig_desc{sizeof(D3D12_DISPATCH_ARGUMENTS), 1, &arg, 0};
        Ref<ID3D12CommandSignature> sig;
        if (FAILED(dev->CreateCommandSignature(&sig_desc, nullptr, IID_PPV_ARGS(&sig.p)))) return false;
        list->DrawInstanced(3, 1, 0, 0);
        list->DrawIndexedInstanced(3, 1, 0, 0, 0);
        list->Dispatch(1, 1, 1);
        list->ExecuteIndirect(sig.p, 1, src.p, 0, nullptr, 0);
    } else {
        list->DrawInstanced(0, 1, 0, 0);
        list->DrawIndexedInstanced(0, 1, 0, 0, 0);
        list->Dispatch(0, 1, 1);
    }
    list->CopyBufferRegion(dst.p, 0, src.p, 0, bytes);
    if (FAILED(list->Close())) return false;
    ID3D12CommandList* submitted[] = {list.p};
    queue->ExecuteCommandLists(1, submitted);
    if (FAILED(queue->Signal(fence.p, 1))) return false;
    HANDLE ready = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!ready) return false;
    const bool complete =
        SUCCEEDED(fence->SetEventOnCompletion(1, ready)) && WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
    CloseHandle(ready);
    if (!complete) return false;
    if (FAILED(dst->Map(0, nullptr, &mapped))) return false;
    unsigned errors = 0;
    for (unsigned i = 0; i < bytes; ++i)
        errors += static_cast<unsigned char*>(mapped)[i] != static_cast<unsigned char>(i ^ 0xa5);
    dst->Unmap(0, nullptr);
    return errors == 0;
}
}  // namespace

int main() {
    if (hostwine::host_is_wine()) return 77;
    vktest::Device vk;
    const auto status = vk.initialize();
    if (status == vktest::DeviceStatus::unavailable) return 77;
    if (status != vktest::DeviceStatus::ready) return 1;
    rt::d3d12::VulkanDeviceInfo info{};
    info.get_instance_proc = vk.instance_proc;
    info.instance = vk.instance;
    info.physical = vk.physical;
    info.device = vk.device;
    info.queue = vk.queue;
    info.queue_family = vk.family;
    Ref<ID3D12Device> layer;
    if (FAILED(rt::d3d12::create_vulkan_device(info, IID_PPV_ARGS(&layer.p)))) return 1;

    Ref<IDXGIFactory4> factory;
    Ref<IDXGIAdapter> adapter;
    Ref<ID3D12Device> warp;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory.p))) ||
        FAILED(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter.p))) ||
        FAILED(D3D12CreateDevice(adapter.p, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&warp.p))))
        return 77;

    constexpr Case cases[] = {
        {"DrawInstanced", Call::draw, false, false},
        {"DrawIndexedInstanced", Call::indexed, false, false},
        {"Dispatch", Call::dispatch, false, false},
        {"DrawInstanced zero", Call::draw, true, false},
        {"DrawIndexedInstanced zero", Call::indexed, true, false},
        {"Dispatch zero", Call::dispatch, true, false},
        {"Bundle DrawInstanced", Call::draw, false, true},
        {"Bundle DrawIndexedInstanced", Call::indexed, false, true},
        {"Bundle Dispatch", Call::dispatch, false, true},
    };
    unsigned failures = 0;
    for (const auto& c : cases) {
        const HRESULT expected = close_case(warp.p, c);
        const HRESULT actual = close_case(layer.p, c);
        const bool ok = (SUCCEEDED(expected) == SUCCEEDED(actual)) && (expected == actual);
        if (!ok) ++failures;
        std::printf("%s WARP=0x%08lx layer=0x%08lx %s\n", c.name, static_cast<unsigned long>(expected),
                    static_cast<unsigned long>(actual), ok ? "PASS" : "FAIL");
    }
    const HRESULT indirect_expected = indirect_dispatch_close(warp.p);
    const HRESULT indirect_actual = indirect_dispatch_close(layer.p);
    const bool indirect_ok = SUCCEEDED(indirect_expected) && indirect_expected == indirect_actual;
    if (!indirect_ok) ++failures;
    std::printf("ExecuteIndirect(DISPATCH) WARP=0x%08lx layer=0x%08lx %s\n",
                static_cast<unsigned long>(indirect_expected), static_cast<unsigned long>(indirect_actual),
                indirect_ok ? "PASS" : "FAIL");
    const bool warp_copy = submit_copy_after_no_pso(warp.p, false);
    const bool layer_copy = submit_copy_after_no_pso(layer.p, true);
    std::printf("null PSO then CopyBufferRegion: WARP=%u layer=%u\n", warp_copy, layer_copy);
    if (!warp_copy || !layer_copy) ++failures;
    std::printf("null PSO cases=%zu failures=%u validation=%u\n", std::size(cases), failures,
                vk.validation_errors());
    return (failures || vk.validation_errors()) ? 1 : 0;
}
