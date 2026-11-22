import Foundation
import LocalAuthentication

let arguments = CommandLine.arguments
guard arguments.count == 2 else { exit(4) }
let context = LAContext()
var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { exit(5) }
context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: arguments[1]) { success, _ in
    exit(success ? 0 : 4)
}
dispatchMain()
