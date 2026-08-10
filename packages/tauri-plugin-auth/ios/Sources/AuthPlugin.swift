import SwiftRs
import Tauri
import UIKit
import AuthenticationServices

struct AuthenticateArgs: Decodable {
    let authUrl: String
    let callbackScheme: String
    let ephemeralSession: Bool?
}

struct AuthResult: Encodable {
    let success: Bool
    let token: String?
    let error: String?
}

class AuthPlugin: Plugin, ASWebAuthenticationPresentationContextProviding {
    /// ASWebAuthenticationSession must be strongly retained for its whole
    /// lifetime: if it is deallocated while the sheet is up, the completion
    /// handler never fires and the caller waits forever, even though the
    /// user finished authenticating.
    private var activeSession: ASWebAuthenticationSession?
    /// Incremented for every new session. Canceling a prior session delivers
    /// its completion asynchronously, after `activeSession` already points at
    /// the replacement; the guard below keeps that stale completion from
    /// releasing the new session.
    private var sessionGeneration = 0

    @objc public func authenticate(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(AuthenticateArgs.self)

        print("Auth URL: \(args.authUrl)")
        print("Callback Scheme: \(args.callbackScheme)")

        guard let authUrl = URL(string: args.authUrl) else {
            invoke.reject("Invalid authentication URL")
            return
        }

        DispatchQueue.main.async {
            // A second authenticate call while a sheet is up would strand the
            // first session; cancel it so its completion resolves as canceled.
            self.activeSession?.cancel()
            self.sessionGeneration += 1
            let generation = self.sessionGeneration

            let session = ASWebAuthenticationSession(url: authUrl, callbackURLScheme: args.callbackScheme) { [weak self] callbackURL, error in
                if self?.sessionGeneration == generation {
                    self?.activeSession = nil
                }
                if let error = error as? ASWebAuthenticationSessionError {
                    switch error.code {
                    case .canceledLogin:
                        print("User canceled login")
                        let result = AuthResult(success: false, token: nil, error: "User canceled login")
                        invoke.resolve(result)
                    case .presentationContextNotProvided:
                        print("Presentation context not provided")
                        let result = AuthResult(success: false, token: nil, error: "Presentation context not provided")
                        invoke.resolve(result)
                    case .presentationContextInvalid:
                        print("Presentation context invalid")
                        let result = AuthResult(success: false, token: nil, error: "Presentation context invalid")
                        invoke.resolve(result)
                    @unknown default:
                        print("Unknown error: \(error.localizedDescription)")
                        let result = AuthResult(success: false, token: nil, error: error.localizedDescription)
                        invoke.resolve(result)
                    }
                } else if let callbackURL = callbackURL {
                    print("Callback URL received: \(callbackURL)")
                    if let urlComponents = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
                       let token = urlComponents.queryItems?.first(where: { $0.name == "token" })?.value {
                        print("Token extracted: \(token)")
                        let result = AuthResult(success: true, token: token, error: nil)
                        invoke.resolve(result)
                    } else {
                        print("Failed to extract token from callback URL")
                        let result = AuthResult(success: false, token: nil, error: "Failed to extract token from callback URL")
                        invoke.resolve(result)
                    }
                } else {
                    print("Unknown error occurred")
                    let result = AuthResult(success: false, token: nil, error: "Unknown error occurred")
                    invoke.resolve(result)
                }
            }
            
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = args.ephemeralSession ?? false
            self.activeSession = session

            if !session.start() {
                print("Failed to start ASWebAuthenticationSession")
                self.activeSession = nil
                invoke.reject("Failed to start authentication session")
            }
        }
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let window = UIApplication.shared.windows.first else {
            fatalError("No window found")
        }
        return window
    }
}

@_cdecl("init_plugin_auth")
func initPlugin() -> Plugin {
    return AuthPlugin()
}