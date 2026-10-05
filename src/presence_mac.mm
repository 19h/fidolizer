#include "fidolizer/presence.hpp"

#import <AppKit/AppKit.h>

#include <optional>

namespace fidolizer {

std::optional<Decision> promptMacApp(std::string_view rp, std::string_view action, bool verification,
                                    const std::function<bool()>& cancelled) {
  if (![NSThread isMainThread]) return std::nullopt;
  @try {
    @autoreleasepool {
      if (cancelled && cancelled()) return Decision::Cancelled;

      NSApplication* app = [NSApplication sharedApplication];
      [app setActivationPolicy:NSApplicationActivationPolicyRegular];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      [app activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop

      NSString* title = verification ? @"Fidolizer verification" : @"Fidolizer";
      NSString* actionText =
          [[NSString alloc] initWithBytes:action.data() length:action.size() encoding:NSUTF8StringEncoding];
      NSString* rpText = [[NSString alloc] initWithBytes:rp.data() length:rp.size() encoding:NSUTF8StringEncoding];
      if (actionText == nil) actionText = @"confirm it is you";
      if (rpText == nil) rpText = @"";

      NSAlert* alert = [[NSAlert alloc] init];
      alert.messageText = title;
      alert.informativeText = [NSString stringWithFormat:@"%@\n%@", actionText, rpText];
      [alert addButtonWithTitle:@"Allow"];
      [alert addButtonWithTitle:@"Deny"];
      alert.window.level = NSFloatingWindowLevel;
      alert.window.collectionBehavior =
          NSWindowCollectionBehaviorMoveToActiveSpace | NSWindowCollectionBehaviorFullScreenAuxiliary;

      // 0 = the button decides, 1 = timeout, 2 = cancelled.
      __block int early = 0;
      dispatch_source_t timer =
          dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
      dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
                                DISPATCH_TIME_FOREVER, 0);
      dispatch_source_set_event_handler(timer, ^{
        if (early == 0) {
          early = 1;
          [NSApp abortModal];
        }
      });
      dispatch_resume(timer);

      dispatch_source_t poll =
          dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
      dispatch_source_set_timer(poll, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                                100 * NSEC_PER_MSEC, 10 * NSEC_PER_MSEC);
      dispatch_source_set_event_handler(poll, ^{
        if (early == 0 && cancelled && cancelled()) {
          early = 2;
          [NSApp abortModal];
        }
      });
      dispatch_resume(poll);

      const NSModalResponse response = [alert runModal];
      dispatch_source_cancel(timer);
      dispatch_source_cancel(poll);
      [app setActivationPolicy:NSApplicationActivationPolicyProhibited];

      if (early == 2) return Decision::Cancelled;
      if (early == 1) return Decision::Timeout;
      if (response == NSAlertFirstButtonReturn) return Decision::Allow;
      if (response == NSAlertSecondButtonReturn) return Decision::Deny;
      return Decision::Timeout;
    }
  } @catch (NSException*) {
    return std::nullopt;
  }
}

}  // namespace fidolizer
