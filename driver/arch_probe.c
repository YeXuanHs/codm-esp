#if defined(_AMD64_)
#pragma message("ARCH _AMD64_ DEFINED")
#else
#pragma message("ARCH _AMD64_ NOT DEFINED")
#endif

#if defined(_KERNEL_MODE)
#pragma message("KERNEL_MODE DEFINED")
#else
#pragma message("KERNEL_MODE NOT DEFINED")
#endif

#if defined(_WIN64)
#pragma message("WIN64 DEFINED")
#else
#pragma message("WIN64 NOT DEFINED")
#endif
