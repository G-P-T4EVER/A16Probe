#import "ContainerProbe.h"
#import <TargetConditionals.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <string.h>

static NSString *ReadSystemString(const char *key) {
    size_t length = 0;
    if (sysctlbyname(key, NULL, &length, NULL, 0) != 0 || length == 0 || length > 4096) {
        return @"unavailable";
    }
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (sysctlbyname(key, data.mutableBytes, &length, NULL, 0) != 0) {
        return @"unavailable";
    }
    const char *bytes = data.bytes;
    size_t count = strnlen(bytes, MIN(length, data.length));
    return [[NSString alloc] initWithBytes:bytes length:count encoding:NSUTF8StringEncoding] ?: @"unavailable";
}

@implementation ContainerProbe
+ (NSDictionary<NSString *, id> *)snapshot {
    // RTLD_NOLOAD refuses to map a new library or run its initializers.
    // An unavailable handle is inconclusive, including on the simulator.
    const char *image = "/usr/lib/system/libsystem_containermanager.dylib";
    dlerror();
    void *handle = dlopen(image, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    const char *loadError = dlerror();
    NSString *imageError = loadError ? [NSString stringWithUTF8String:loadError] : @"";
    NSArray<NSString *> *names = @[
        @"container_query_create", @"container_query_set_class",
        @"container_query_set_group_identifiers", @"container_query_operation_set_flags",
        @"container_query_operation_set_part", @"container_query_get_single_result",
        @"container_query_free", @"container_copy_sandbox_token",
        @"sandbox_extension_consume", @"sandbox_extension_release"
    ];
    NSMutableArray<NSDictionary *> *symbols = [NSMutableArray array];
    for (NSString *name in names) {
        BOOL extension = [name hasPrefix:@"sandbox_extension_"];
        void *scope = extension ? RTLD_DEFAULT : handle;
        if (!extension && !handle) {
            [symbols addObject:@{@"name": name, @"status": @"notChecked",
                                 @"reason": @"imageNotAlreadyLoaded", @"invoked": @NO}];
            continue;
        }
        dlerror();
        void *address = dlsym(scope, name.UTF8String);
        const char *symbolError = dlerror();
        BOOL visible = address != NULL && symbolError == NULL;
        // Never cast this address to a function pointer, invoke it, or log the address.
        [symbols addObject:@{@"name": name, @"status": visible ? @"visible" : @"notVisible",
                             @"scope": extension ? @"RTLD_DEFAULT" : @"alreadyLoadedImage",
                             @"reason": visible ? @"resolvedOnly" : @"notVisibleInSelectedScope",
                             @"invoked": @NO}];
    }
    if (handle) { dlclose(handle); }
    NSFileManager *manager = NSFileManager.defaultManager;
    NSArray *publicAPIs = @[
        @{@"name": @"NSFileManager.URLsForDirectory:inDomains:",
          @"available": @([manager respondsToSelector:@selector(URLsForDirectory:inDomains:)])},
        @{@"name": @"NSFileManager.containerURLForSecurityApplicationGroupIdentifier:",
          @"available": @([manager respondsToSelector:@selector(containerURLForSecurityApplicationGroupIdentifier:)])},
        @{@"name": @"NSJSONSerialization.dataWithJSONObject:options:error:",
          @"available": @([NSJSONSerialization respondsToSelector:@selector(dataWithJSONObject:options:error:)])}
    ];
    return @{
        @"hardwareIdentifier": ReadSystemString("hw.machine"),
        @"osBuild": ReadSystemString("kern.osversion"),
        @"simulator": @(TARGET_OS_SIMULATOR != 0),
        @"containerManager": @{@"mode": @"alreadyLoadedImagesOnly",
                               @"imageAlreadyLoaded": @(handle != NULL),
                               @"loaderDiagnostic": imageError ?: @"",
                               @"symbols": symbols},
        @"publicAPIs": publicAPIs,
        @"privateAPIsInvoked": @NO,
        @"containerQueriesSent": @NO,
        @"sandboxExtensionsConsumed": @NO,
        @"appGroupLookupPerformed": @NO
    };
}
@end
