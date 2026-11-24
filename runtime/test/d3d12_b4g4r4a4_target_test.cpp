// LOCAL STAND-IN (boot-chain test, not for upstream): a DXGI_FORMAT_B4G4R4A4_UNORM render target on a Vulkan GPU that
// renders to no 4-4-4-4 format is an A1R5G5B5_UNORM_PACK16 image (DeviceState::b4g4r4a4_target_as_a1r5g5b5 in
// d3d12_vulkan_device.cpp).
//
// Exercises:
//   1. GetResourceAllocationInfo and CreateCommittedResource for a 2560x1440 render target (the shape a title's boot
//      asks for; the size was UINT64_MAX), which keeps its description
//   2. The SRV T# names GFX10's 1_5_5_5_UNORM format, with a null description and with a B4G4R4A4 one
//   3. A B4G4R4A4 texture that is not a render target is still a 4_4_4_4 image, and a render target that also allows
//      unordered access is still refused
// Drawing into such a target is d3d12_draw_test's. On a GPU that renders to A4R4G4B4, or not to A1R5G5B5, nothing is
// replaced and the test exits 77.
//
// Synthetic data only; no game files. Set LEONIDA_VK_VALIDATION=1 to run under VK_LAYER_KHRONOS_validation.
#include "vk_test_device.h"
#include "../shims/d3d12_com.h"
#include "../src/gfx10_descriptors.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#define EXPECT(condition) do { \
    if (!(condition)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; } \
} while (0)

namespace {

namespace g = leonida::gfx10;

template<class T>
struct Ref {
    T* p = nullptr;
    ~Ref() { reset(); }
    void reset() {
        if (p) p->Release();
        p = nullptr;
    }
    T* operator->() const { return p; }
};

D3D12_RESOURCE_DESC tex_desc(UINT64 width, UINT height, D3D12_RESOURCE_FLAGS flags) {
    D3D12_RESOURCE_DESC d{};
    d.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    d.Width = width;
    d.Height = height;
    d.DepthOrArraySize = 1;
    d.MipLevels = 1;
    d.Format = DXGI_FORMAT_B4G4R4A4_UNORM;
    d.SampleDesc = {1, 0};
    d.Flags = flags;
    return d;
}

// GFX10 T# word 1 bits 20..28: the FORMAT field.
std::uint32_t tsharp_format(D3D12_CPU_DESCRIPTOR_HANDLE descriptor) {
    std::uint32_t words[8] = {};
    std::memcpy(words, reinterpret_cast<const void*>(descriptor.ptr), sizeof(words));
    return (words[1] >> 20) & 0x1ff;
}

}  // namespace

int main() {
    vktest::Device d;
    const auto status = d.initialize();
    if (status == vktest::DeviceStatus::unavailable) return 77;
    if (status != vktest::DeviceStatus::ready) return 1;

    const auto features = [&](VkFormat format) {
        VkFormatProperties props{};
        d.instance_fn<PFN_vkGetPhysicalDeviceFormatProperties>("vkGetPhysicalDeviceFormatProperties")(
            d.physical, format, &props);
        return props.optimalTilingFeatures;
    };
    if ((features(VK_FORMAT_A4R4G4B4_UNORM_PACK16) & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT) ||
        !(features(VK_FORMAT_A1R5G5B5_UNORM_PACK16) & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT)) {
        std::printf("this GPU renders to A4R4G4B4, or not to A1R5G5B5: nothing is replaced, skipping\n");
        return 77;
    }

    rt::d3d12::VulkanDeviceInfo info{};
    info.get_instance_proc = d.instance_proc;
    info.instance = d.instance;
    info.physical = d.physical;
    info.device = d.device;
    info.queue = d.queue;
    info.queue_family = d.family;
    info.bindless = d.bindless;
    info.bindless_partially_bound = d.partially_bound;
    info.image_view_min_lod = d.image_view_min_lod;
    info.host_image_copy = d.host_image_copy;
    Ref<ID3D12Device> device;
    EXPECT(SUCCEEDED(rt::d3d12::create_vulkan_device(info, IID_PPV_ARGS(&device.p))));
    const D3D12_HEAP_PROPERTIES def_heap{D3D12_HEAP_TYPE_DEFAULT};

    // 1. The boot's shape: the size of a 16-bit texture, and a resource that keeps its description.
    const auto big = tex_desc(2560, 1440, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET);
    const auto big_info = device->GetResourceAllocationInfo(0, 1, &big);
    EXPECT(big_info.SizeInBytes >= 2560ull * 1440 * 2 && big_info.SizeInBytes < 2560ull * 1440 * 4);
    Ref<ID3D12Resource> target, sampled;
    EXPECT(SUCCEEDED(device->CreateCommittedResource(&def_heap, D3D12_HEAP_FLAG_NONE, &big, D3D12_RESOURCE_STATE_COMMON,
                                                     nullptr, IID_PPV_ARGS(&target.p))));
    EXPECT(target->GetDesc().Format == DXGI_FORMAT_B4G4R4A4_UNORM &&
           target->GetDesc().Flags == D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET);

    // 3. With unordered access too the stand-in does not apply (refused, as before); without the render-target flag
    // the texture is the 4-4-4-4 image it always was.
    const auto with_uav = tex_desc(64, 32, D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET |
                                               D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS);
    EXPECT(device->GetResourceAllocationInfo(0, 1, &with_uav).SizeInBytes == UINT64_MAX);
    const auto sampled_desc = tex_desc(64, 32, D3D12_RESOURCE_FLAG_NONE);
    EXPECT(SUCCEEDED(device->CreateCommittedResource(&def_heap, D3D12_HEAP_FLAG_NONE, &sampled_desc,
                                                     D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&sampled.p))));

    // 2 and 3. The render target's SRVs name 1_5_5_5 (its image), the plain texture's 4_4_4_4.
    Ref<ID3D12DescriptorHeap> heap;
    const D3D12_DESCRIPTOR_HEAP_DESC heap_desc{D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, 3,
                                               D3D12_DESCRIPTOR_HEAP_FLAG_NONE};
    EXPECT(SUCCEEDED(device->CreateDescriptorHeap(&heap_desc, IID_PPV_ARGS(&heap.p))));
    const UINT step = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    D3D12_CPU_DESCRIPTOR_HANDLE srv[3];
    for (UINT i = 0; i < 3; ++i) srv[i].ptr = heap->GetCPUDescriptorHandleForHeapStart().ptr + i * step;
    D3D12_SHADER_RESOURCE_VIEW_DESC typed{};
    typed.Format = DXGI_FORMAT_B4G4R4A4_UNORM;
    typed.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
    typed.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    typed.Texture2D.MipLevels = 1;
    device->CreateShaderResourceView(target.p, nullptr, srv[0]);
    device->CreateShaderResourceView(target.p, &typed, srv[1]);
    device->CreateShaderResourceView(sampled.p, &typed, srv[2]);
    const std::uint32_t code_1555 = g::format_from_vulkan(VK_FORMAT_A1R5G5B5_UNORM_PACK16);
    const std::uint32_t code_4444 = g::format_from_vulkan(VK_FORMAT_A4R4G4B4_UNORM_PACK16);
    EXPECT(code_1555 != 0 && code_4444 != 0 && code_1555 != code_4444);
    EXPECT(tsharp_format(srv[0]) == code_1555);
    EXPECT(tsharp_format(srv[1]) == code_1555);
    EXPECT(tsharp_format(srv[2]) == code_4444);

    heap.reset();
    sampled.reset();
    target.reset();
    device.reset();
    if (d.validation_errors()) {
        std::fprintf(stderr, "%u Vulkan validation errors\n", d.validation_errors());
        return 1;
    }
    std::printf("d3d12_b4g4r4a4_target_test: OK (A1R5G5B5 image, 2560x1440 sized %llu B, SRV T# format %u, a plain "
                "texture's %u, 0 validation errors)\n",
                static_cast<unsigned long long>(big_info.SizeInBytes), static_cast<unsigned>(code_1555),
                static_cast<unsigned>(code_4444));
    return 0;
}
