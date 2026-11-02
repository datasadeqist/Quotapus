// Quotapus: a menu bar meter for several Claude Code accounts.
// One bar per account shows how much of its usage limit is left. Click for the details.
// Accounts are added by signing in to them in Claude Code (/login): Quotapus copies each login
// into its own Keychain item, so it can keep reading usage after you switch to another account.
import AppKit
import SwiftUI
import ServiceManagement
import Security
import Network
import CryptoKit

let clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"   // Claude Code's OAuth client
let tokenURL = URL(string: "https://platform.claude.com/v1/oauth/token")!
let apiBase = "https://api.anthropic.com/api/oauth/"
let service = "Quotapus"

struct Creds: Codable, Equatable { var access: String; var refresh: String; var expiresAt: Double }   // ms

struct Limit: Identifiable {
    let id = UUID(); let name: String; let used: Double; let resets: Date?; let active: Bool
    var left: Double { max(0, 100 - used) }
}

struct Account: Identifiable {
    let email: String
    var limits: [Limit] = []
    var error: String?
    var id: String { email }
    /// Share used of the tightest limit that applies now. The menu bar and the ring show this.
    var used: Double? { left.map { 100 - $0 } }
    var left: Double? {
        let on = limits.filter(\.active)
        return (on.isEmpty ? limits : on).map(\.left).min()
    }
}

enum HTTPError: Error { case status(Int) }

let logPath = ("~/Library/Logs/Quotapus.log" as NSString).expandingTildeInPath
/// One line per call to Claude. Example: "2026-11-02 01:10:00 usage eli@sociahive.com 200".
func logCall(_ what: String, _ who: String, _ status: Int) {
    let line = "\(Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false))) \(what) \(who) \(status)\n"
    if let h = FileHandle(forWritingAtPath: logPath) { h.seekToEndOfFile(); h.write(Data(line.utf8)); try? h.close() }
    else { try? line.write(toFile: logPath, atomically: true, encoding: .utf8) }
}

// MARK: - Keychain

enum Keychain {
    static func query(_ email: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: email]
    }
    static func get(_ email: String) -> Creds? {
        var q = query(email); q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return try? JSONDecoder().decode(Creds.self, from: d)
    }
    static func set(_ email: String, _ c: Creds) {
        guard get(email) != c, let d = try? JSONEncoder().encode(c) else { return }
        SecItemDelete(query(email) as CFDictionary)
        var q = query(email); q[kSecValueData as String] = d
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }
    static func delete(_ email: String) { SecItemDelete(query(email) as CFDictionary) }

    /// The login Claude Code is using now. Read through /usr/bin/security, which Claude Code's
    /// Keychain item already trusts, so macOS does not ask for permission.
    static func claudeCode() -> Creds? {
        let p = Process(); let pipe = Pipe()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", "Claude Code-credentials", "-w"]
        p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        guard p.terminationStatus == 0,
              let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let o = j["claudeAiOauth"] as? [String: Any],
              let a = o["accessToken"] as? String, let r = o["refreshToken"] as? String else { return nil }
        return Creds(access: a, refresh: r, expiresAt: (o["expiresAt"] as? Double) ?? 0)
    }
}

// MARK: - Anthropic API

func getJSON(_ path: String, _ token: String, who: String = "") async throws -> [String: Any] {
    var r = URLRequest(url: URL(string: apiBase + path)!, timeoutInterval: 20)
    r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    r.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
    let (d, resp) = try await URLSession.shared.data(for: r)
    let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
    logCall(path, who, code)
    guard code == 200 else { throw HTTPError.status(code) }
    return (try JSONSerialization.jsonObject(with: d) as? [String: Any]) ?? [:]
}

/// Refresh tokens rotate: the old one stops working, so the new pair must be saved right away.
func renew(_ c: Creds, who: String) async throws -> Creds {
    var r = URLRequest(url: tokenURL, timeoutInterval: 20)
    r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type")
    r.httpBody = try JSONSerialization.data(withJSONObject:
        ["grant_type": "refresh_token", "refresh_token": c.refresh, "client_id": clientID])
    let (d, resp) = try await URLSession.shared.data(for: r)
    let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
    logCall("renew", who, code)
    guard code == 200, let j = try JSONSerialization.jsonObject(with: d) as? [String: Any],
          let a = j["access_token"] as? String else { throw HTTPError.status(code == 200 ? 0 : code) }
    let expires = (j["expires_in"] as? Double) ?? 3600
    return Creds(access: a, refresh: (j["refresh_token"] as? String) ?? c.refresh,
                 expiresAt: (Date().timeIntervalSince1970 + expires) * 1000)
}

func parseLimits(_ u: [String: Any]) -> [Limit] {
    let iso = ISO8601DateFormatter(); iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let iso2 = ISO8601DateFormatter()
    func date(_ v: Any?) -> Date? { (v as? String).flatMap { iso.date(from: $0) ?? iso2.date(from: $0) } }
    if let list = u["limits"] as? [[String: Any]], !list.isEmpty {
        return list.map { l in
            let kind = l["kind"] as? String ?? ""
            let model = ((l["scope"] as? [String: Any])?["model"] as? [String: Any])?["display_name"] as? String
            let weekly = (l["group"] as? String) == "weekly"
            let name = kind == "session" ? "Current session"
                : weekly ? "Current week (\(model ?? "all models"))" : kind.capitalized
            return Limit(name: name, used: (l["percent"] as? Double) ?? 0, resets: date(l["resets_at"]),
                         active: (l["is_active"] as? Bool) ?? true)
        }
    }
    // Older shape of the same answer.
    return [("five_hour", "Current session"), ("seven_day", "Current week (all models)")].compactMap { key, name in
        guard let w = u[key] as? [String: Any], let used = w["utilization"] as? Double else { return nil }
        return Limit(name: name, used: used, resets: date(w["resets_at"]), active: true)
    }
}

// MARK: - Sign in (same OAuth flow as Claude Code, with a localhost callback)

let authorizeURL = "https://claude.com/cai/oauth/authorize"

func base64url(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
func randomString() -> String {
    var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
    return base64url(Data(b))
}

/// Opens the Claude sign-in page in the browser and waits for it to call back on localhost.
final class SignIn {
    let verifier = randomString(), state = randomString()
    var listener: NWListener?
    var done: ((Creds?) -> Void)?
    var port: UInt16 = 0

    func start(_ completion: @escaping (Creds?) -> Void) {
        done = completion
        guard let l = try? NWListener(using: .tcp, on: .any) else { return finish(nil) }
        listener = l
        l.newConnectionHandler = { [weak self] c in self?.handle(c) }
        l.stateUpdateHandler = { [weak self] s in
            guard let self else { return }
            if case .ready = s, let p = l.port?.rawValue { self.port = p; DispatchQueue.main.async { self.openBrowser() } }
            if case .failed = s { self.finish(nil) }
        }
        l.start(queue: .main)
    }

    func openBrowser() {
        let challenge = base64url(Data(SHA256.hash(data: Data(verifier.utf8))))
        var c = URLComponents(string: authorizeURL)!
        c.queryItems = [.init(name: "code", value: "true"), .init(name: "client_id", value: clientID),
                        .init(name: "response_type", value: "code"),
                        .init(name: "redirect_uri", value: "http://localhost:\(port)/callback"),
                        .init(name: "scope", value: "user:profile"),
                        .init(name: "code_challenge", value: challenge), .init(name: "code_challenge_method", value: "S256"),
                        .init(name: "state", value: state)]
        let url = c.url!
        // Prefer Chrome when it's installed: that's where the user's claude.ai sessions are.
        if let chrome = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.google.Chrome") {
            NSWorkspace.shared.open([url], withApplicationAt: chrome, configuration: NSWorkspace.OpenConfiguration())
        } else { NSWorkspace.shared.open(url) }
    }

    func handle(_ conn: NWConnection) {
        conn.start(queue: .main)
        conn.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] data, _, _, _ in
            guard let self else { return }
            let line = data.flatMap { String(data: $0, encoding: .utf8) }?.components(separatedBy: "\r\n").first ?? ""
            let path = line.split(separator: " ").dropFirst().first.map(String.init) ?? ""
            let q = URLComponents(string: "http://localhost" + path)?.queryItems ?? []
            let code = q.first { $0.name == "code" }?.value?.components(separatedBy: "#").first
            let ok = path.hasPrefix("/callback") && q.first { $0.name == "state" }?.value == self.state && code != nil
            let body = ok ? "<h2>Signed in. You can close this tab and go back to Quotapus.</h2>"
                          : "<h2>Quotapus could not sign in. Close this tab and try again.</h2>"
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
                + "<html><body style=\"font:15px -apple-system;padding:40px\">\(body)</body></html>"
            conn.send(content: Data(resp.utf8), completion: .contentProcessed { _ in conn.cancel() })
            guard path.hasPrefix("/callback") else { return }   // ignore favicon and the like
            guard ok, let code else { return self.finish(nil) }
            Task { @MainActor in self.finish(try? await self.exchange(code)) }
        }
    }

    func exchange(_ code: String) async throws -> Creds {
        var r = URLRequest(url: tokenURL, timeoutInterval: 20)
        r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try JSONSerialization.data(withJSONObject: [
            "grant_type": "authorization_code", "code": code, "redirect_uri": "http://localhost:\(port)/callback",
            "client_id": clientID, "code_verifier": verifier, "state": state])
        let (d, resp) = try await URLSession.shared.data(for: r)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        logCall("sign-in", "", status)
        guard status == 200, let j = try JSONSerialization.jsonObject(with: d) as? [String: Any],
              let a = j["access_token"] as? String, let rt = j["refresh_token"] as? String else { throw HTTPError.status(status) }
        return Creds(access: a, refresh: rt,
                     expiresAt: (Date().timeIntervalSince1970 + ((j["expires_in"] as? Double) ?? 3600)) * 1000)
    }

    func finish(_ c: Creds?) {
        listener?.cancel(); listener = nil
        let d = done; done = nil
        DispatchQueue.main.async { d?(c) }
    }
}

// MARK: - Model

@MainActor final class Model: ObservableObject {
    @AppStorage("emails") var emailsRaw = ""          // account order, comma separated
    @Published var accounts: [Account] = []
    @Published var activeEmail: String?              // the account Claude Code is signed in to
    @Published var updated: Date?
    @Published var loading = false
    @Published var showHint = false
    @Published var signingIn = false
    @Published var signInError: String?
    private var signIn: SignIn?
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled
    var onChange: () -> Void = {}
    private var lastSeen: Creds?                      // Claude Code's login the last time we looked
    /// After a failed call, leave that account alone for a while instead of retrying every cycle.
    private var pausedUntil: [String: Date] = [:]

    init() { accounts = emailsRaw.split(separator: ",").map { Account(email: String($0)) } }

    func setOpenAtLogin(_ on: Bool) {
        do { if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
        catch { NSLog("Quotapus: login item change failed: \(error.localizedDescription)") }
        openAtLogin = SMAppService.mainApp.status == .enabled
    }

    func addAccount() {
        signIn?.finish(nil)
        signingIn = true; signInError = nil
        let s = SignIn(); signIn = s
        s.start { [weak self] c in
            guard let self, self.signIn === s else { return }
            self.signIn = nil
            Task { @MainActor in
                defer { self.signingIn = false }
                guard let c, let p = try? await getJSON("profile", c.access),
                      let email = (p["account"] as? [String: Any])?["email"] as? String else {
                    self.signInError = "Sign-in didn't finish. Try again."; return
                }
                Keychain.set(email, c); self.pausedUntil[email] = nil
                if !self.accounts.contains(where: { $0.email == email }) {
                    self.accounts.append(Account(email: email))
                    self.emailsRaw = self.accounts.map(\.email).joined(separator: ",")
                }
                await self.refreshAll()
            }
        }
    }
    func cancelSignIn() { signIn?.finish(nil); signIn = nil; signingIn = false }

    func remove(_ email: String) {
        Keychain.delete(email)
        accounts.removeAll { $0.email == email }
        emailsRaw = accounts.map(\.email).joined(separator: ",")
        onChange()
    }

    /// Notice a new or renewed Claude Code login and save a copy. Returns true when an account was added.
    @discardableResult func syncClaudeCode() async -> Bool {
        guard let cc = Keychain.claudeCode() else { activeEmail = nil; return false }
        if cc == lastSeen { return false }
        // Same login we already hold (matched by refresh token): no network needed.
        if let known = accounts.first(where: { Keychain.get($0.email)?.refresh == cc.refresh }) {
            Keychain.set(known.email, cc); activeEmail = known.email; lastSeen = cc; pausedUntil[known.email] = nil; return false
        }
        lastSeen = cc   // look this login up once; a failed lookup waits for Claude Code's next change
        guard cc.expiresAt / 1000 > Date().timeIntervalSince1970 + 30,
              let p = try? await getJSON("profile", cc.access, who: "claude-code"),
              let email = (p["account"] as? [String: Any])?["email"] as? String else { activeEmail = nil; return false }
        Keychain.set(email, cc); activeEmail = email; pausedUntil[email] = nil
        guard !accounts.contains(where: { $0.email == email }) else { return false }
        accounts.append(Account(email: email))
        emailsRaw = accounts.map(\.email).joined(separator: ",")
        showHint = false
        return true
    }

    func refreshAll() async {
        guard !loading else { return }
        loading = true; defer { loading = false; updated = Date(); onChange() }
        await syncClaudeCode()
        for a in accounts { await update(a.email) }
    }

    func refreshIfStale() { if (updated.map { -$0.timeIntervalSinceNow } ?? .infinity) > 300 { Task { await refreshAll() } } }

    private func update(_ email: String) async {
        guard let i = accounts.firstIndex(where: { $0.email == email }) else { return }
        if let p = pausedUntil[email], p > Date() { return }
        guard var c = Keychain.get(email) else { accounts[i].error = "Sign in to it in Claude Code again"; return }
        do {
            if c.expiresAt / 1000 < Date().timeIntervalSince1970 + 60 {
                // Never renew a login Claude Code may still hold: renewing it would sign Claude Code out.
                // ponytail: if Claude Code's login can't be identified, every account waits; fine, it is rare.
                guard let active = activeEmail, active != email else {
                    accounts[i].error = "Open Claude Code to renew this login"; return
                }
                c = try await renew(c, who: email); Keychain.set(email, c)
            }
            let u = try await getJSON("usage", c.access, who: email)
            guard let j = accounts.firstIndex(where: { $0.email == email }) else { return }
            accounts[j].limits = parseLimits(u); accounts[j].error = nil
        } catch HTTPError.status(let code) where [400, 401, 403].contains(code) {
            pausedUntil[email] = .distantFuture   // signed out: no more calls until it is added again
            if let j = accounts.firstIndex(where: { $0.email == email }) {
                accounts[j].error = "Signed out. Sign in to it in Claude Code (/login) again"; accounts[j].limits = []
            }
        } catch {
            // Rate limited, server error or offline: wait 30 min before trying this account again.
            pausedUntil[email] = Date().addingTimeInterval(1800)
            if let j = accounts.firstIndex(where: { $0.email == email }) { accounts[j].error = "Couldn't reach Claude. Showing the last numbers" }
        }
    }
}

// MARK: - Panel

struct IconRow<Trailing: View>: View {
    let icon: String; let title: String; let action: (() -> Void)?
    @ViewBuilder var trailing: Trailing
    @State private var hover = false
    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: icon).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary).frame(width: 16)
            Text(title).font(.system(size: 13))
            Spacer()
            trailing
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(RoundedRectangle(cornerRadius: 8).fill(hover && action != nil ? Color.primary.opacity(0.08) : .clear))
        .contentShape(Rectangle()).onHover { hover = $0 }
        .onTapGesture { action?() }
    }
}

let shadowRoom: CGFloat = 24   // transparent margin so the shadow is not clipped

/// Same steps as Claude: calm until 75% used, then orange, red from 90%.
func usedColor(_ used: Double) -> Color { used >= 90 ? .red : used >= 75 ? .orange : .blue }

func resetText(_ d: Date) -> String {
    Calendar.current.isDateInToday(d) ? "Resets " + d.formatted(date: .omitted, time: .shortened)
        : "Resets " + d.formatted(.dateTime.weekday(.abbreviated).hour().minute())
}

struct Ring: View {
    let used: Double?
    var body: some View {
        ZStack {
            Circle().stroke(Color.primary.opacity(0.1), lineWidth: 4)
            if let used {
                Circle().trim(from: 0, to: used / 100)
                    .stroke(usedColor(used), style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text("\(Int(used.rounded()))%").font(.system(size: 11, weight: .semibold, design: .rounded).monospacedDigit())
            } else {
                Image(systemName: "exclamationmark").font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
            }
        }
        .frame(width: 38, height: 38)
        .animation(.easeOut(duration: 0.4), value: used)
    }
}

struct Bar: View {
    let used: Double
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.primary.opacity(0.1))
                Capsule().fill(usedColor(used)).frame(width: used > 0 ? max(4, g.size.width * used / 100) : 0)
            }
        }
        .frame(height: 5)
        .animation(.easeOut(duration: 0.4), value: used)
    }
}

struct AccountView: View {
    let a: Account; let active: Bool; let remove: () -> Void
    @State private var hover = false
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Ring(used: a.error == nil || !a.limits.isEmpty ? a.used : nil)
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 6) {
                    Text(a.email).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                    if active {
                        Circle().fill(.green).frame(width: 6, height: 6).help("Claude Code is signed in to this account")
                    }
                    Spacer(minLength: 0)
                    Button(action: remove) { Image(systemName: "xmark.circle.fill").font(.system(size: 12)) }
                        .buttonStyle(.plain).foregroundStyle(.tertiary).opacity(hover ? 1 : 0)
                        .help("Remove this account from Quotapus")
                }
                ForEach(a.limits) { l in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 4) {
                            Text(l.name).font(.system(size: 11, weight: .medium))
                            if let r = l.resets {
                                Text("· \(resetText(r))").font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("\(Int(l.used.rounded()))% used").font(.system(size: 11, weight: .semibold).monospacedDigit())
                                .foregroundStyle(l.used >= 75 ? usedColor(l.used) : .primary)
                        }
                        Bar(used: l.used)
                    }
                    .opacity(l.active ? 1 : 0.6)
                }
                if let e = a.error {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if a.limits.isEmpty {
                    Text("Checking…").font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.primary.opacity(hover ? 0.07 : 0.045)))
        .onHover { hover = $0 }
    }
}

struct Panel: View {
    @ObservedObject var m: Model
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text("Quotapus").font(.system(size: 15, weight: .bold, design: .rounded))
                Text("Claude Code usage").font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
            }.padding(.horizontal, 6).padding(.top, 4)
            if m.accounts.isEmpty {
                Text("No accounts yet. Quotapus adds the account Claude Code is signed in to.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).padding(.horizontal, 6)
            }
            ForEach(m.accounts) { a in
                AccountView(a: a, active: a.email == m.activeEmail) { m.remove(a.email) }
            }
            VStack(spacing: 0) {
                IconRow(icon: "plus.circle", title: m.signingIn ? "Waiting for sign-in in Chrome…" : "Add account…",
                        action: { m.signingIn ? m.cancelSignIn() : m.addAccount() }) {
                    if m.signingIn { Text("Cancel").font(.system(size: 11)).foregroundStyle(.secondary) }
                }
                if m.signingIn || m.signInError != nil {
                    Text(m.signInError ?? "Approve Quotapus on the Claude page. It adds the account that page is signed in to, so switch accounts on claude.ai first if needed.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                        .padding(.leading, 33).padding(.trailing, 8).padding(.bottom, 4)
                        .fixedSize(horizontal: false, vertical: true)
                }
                IconRow(icon: "arrow.clockwise", title: "Refresh", action: { Task { await m.refreshAll() } }) {
                    if m.loading { ProgressView().controlSize(.mini) }
                    else if let u = m.updated {
                        Text(u.formatted(date: .omitted, time: .shortened)).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                IconRow(icon: "power", title: "Open at login", action: nil) {
                    Toggle("", isOn: Binding(get: { m.openAtLogin }, set: { m.setOpenAtLogin($0) }))
                        .toggleStyle(.switch).labelsHidden().controlSize(.mini)
                }
                IconRow(icon: "xmark.square", title: "Quit Quotapus", action: { NSApp.terminate(nil) }) { EmptyView() }
            }
        }
        .padding(8)
        .frame(width: 340)
        .glassEffect(.regular, in: .rect(cornerRadius: 18))
        .shadow(color: .black.opacity(0.22), radius: 14, y: 6)
        .padding(shadowRoom)
    }
}

// MARK: - Panel window that stays under the menu bar item and closes on outside clicks

final class AnchoredPanel: NSPanel {
    var topRight: NSPoint = .zero
    override var canBecomeKey: Bool { true }
    override func setFrame(_ r: NSRect, display: Bool) {
        var f = r; f.origin = NSPoint(x: topRight.x - f.width, y: topRight.y - f.height)
        super.setFrame(f, display: display)
    }
    override func cancelOperation(_ sender: Any?) { orderOut(nil) }   // Esc
}

@MainActor final class App: NSObject, NSApplicationDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let model = Model()
    var panel: AnchoredPanel!
    var outsideClick: Any?

    func applicationDidFinishLaunching(_ n: Notification) {
        let host = NSHostingController(rootView: Panel(m: model))
        host.sizingOptions = .preferredContentSize
        host.view.wantsLayer = true; host.view.layer?.backgroundColor = .clear
        panel = AnchoredPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        panel.contentViewController = host
        panel.isOpaque = false; panel.backgroundColor = .clear; panel.hasShadow = false
        panel.level = .statusBar; panel.isMovable = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

        item.button?.target = self; item.button?.action = #selector(toggle)
        model.onChange = { [weak self] in self?.updateButton() }
        updateButton()
        Task { await model.refreshAll() }
        // Every 30 s: look for a new Claude Code login (cheap, no network unless it changed).
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let m = self?.model else { return }
                if await m.syncClaudeCode() { await m.refreshAll() }
            }
        }
        // Every 15 min: read usage for every account (4 accounts = about 400 light calls a day).
        Timer.scheduledTimer(withTimeInterval: 900, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.model.refreshAll() }
        }
    }

    func updateButton() {
        guard let b = item.button else { return }
        if model.accounts.isEmpty {
            b.image = NSImage(systemSymbolName: "gauge.with.dots.needle.33percent", accessibilityDescription: "Claude usage")
            b.image?.isTemplate = true
            b.toolTip = "Quotapus: sign in to Claude Code to add an account"
            return
        }
        b.image = bars(model.accounts.map(\.used))
        b.toolTip = model.accounts.map { a in
            "\(a.email): " + (a.used.map { "\(Int($0.rounded()))% used" } ?? (a.error ?? "checking"))
        }.joined(separator: "\n")
    }

    /// One bar per account, filled by the share used, as in Claude. Drawn on demand, so it follows light and dark menu bars.
    func bars(_ values: [Double?]) -> NSImage {
        let w: CGFloat = 4, gap: CGFloat = 2.5, h: CGFloat = 15
        let size = NSSize(width: CGFloat(values.count) * (w + gap) - gap, height: h)
        let img = NSImage(size: size, flipped: false) { _ in
            for (i, v) in values.enumerated() {
                let x = CGFloat(i) * (w + gap)
                NSColor.labelColor.withAlphaComponent(0.22).setFill()
                NSBezierPath(roundedRect: NSRect(x: x, y: 0, width: w, height: h), xRadius: 1.5, yRadius: 1.5).fill()
                guard let v else { continue }
                guard v > 0 else { continue }
                (v >= 90 ? NSColor.systemRed : v >= 75 ? NSColor.systemOrange : NSColor.labelColor).setFill()
                let fill = max(1.5, h * CGFloat(v) / 100)
                NSBezierPath(roundedRect: NSRect(x: x, y: 0, width: w, height: fill), xRadius: 1.5, yRadius: 1.5).fill()
            }
            return true
        }
        img.accessibilityDescription = "Claude usage used per account"
        return img
    }

    @objc func toggle() { panel.isVisible ? close() : open() }

    func open() {
        guard let b = item.button, let w = b.window, let screen = w.screen else { return }
        model.refreshIfStale()
        let icon = w.convertToScreen(b.convert(b.bounds, to: nil))
        let width: CGFloat = 340
        let right = min(icon.midX + width / 2, screen.visibleFrame.maxX - 6) + shadowRoom
        panel.topRight = NSPoint(x: max(right, screen.visibleFrame.minX + width + 6 + shadowRoom),
                                 y: screen.visibleFrame.maxY - 4 + shadowRoom)
        panel.setFrame(NSRect(origin: .zero, size: panel.contentViewController!.preferredContentSize), display: false)
        panel.alphaValue = 0
        panel.makeKeyAndOrderFront(nil)
        NSAnimationContext.runAnimationGroup { $0.duration = 0.15; panel.animator().alphaValue = 1 }
        outsideClick = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            DispatchQueue.main.async { self?.close() }
        }
    }

    func close() {
        if let m = outsideClick { NSEvent.removeMonitor(m); outsideClick = nil }
        let p = panel!
        NSAnimationContext.runAnimationGroup({ $0.duration = 0.12; p.animator().alphaValue = 0 },
                                             completionHandler: { p.orderOut(nil) })
    }
}

let app = NSApplication.shared
let delegate = MainActor.assumeIsolated { App() }
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
