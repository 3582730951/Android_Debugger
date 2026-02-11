# Example Syscall Bridge Plugin

This folder is a manifest-only sample for testers and developers.

## Use
1. Open `设置 -> 插件与自定义syscall`.
2. Set plugin root to `core/plugins`.
3. Select `Example Syscall Bridge`.
4. Enable plugin provider and keep fallback enabled.
5. Verify `syscall_read/syscall_write` values match target kernel.
6. Use `扫描插件` after changing plugin root to refresh list immediately.

## Vendor Context Example
`user_ctx_hex` is encoded as:

```c
#pragma pack(push, 1)
struct VendorMemCtxV1 {
  uint32_t version; // 1
  uint32_t policy;  // 1
  uint64_t token;   // 42
};
#pragma pack(pop)
```
