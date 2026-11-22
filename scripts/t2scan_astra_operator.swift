import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

private enum ApprovalError: Error {
    case invalid
    case hardwareUnavailable
    case cancelled
}

private let signatureDomain = Data("Agent Harness T2Scan Astra direct approval v1\u{0}".utf8)
private let roles = [
    "executive-synthesis": "Executive synthesis",
    "assurance-synthesis": "Assurance synthesis",
    "delivery-synthesis": "Delivery synthesis",
]

private func matches(_ text: String, _ pattern: String) -> Bool {
    text.range(of: "\\A(?:\(pattern))\\z", options: .regularExpression) != nil
}

private struct Enrollment: Codable {
    let issuer: String
    let audience: String
    let keyHandle: Data
}

private struct Challenge: Codable {
    struct Assignment: Codable {
        let assignment: String
        let work_item_id: String
        let task_key: String
        let packet_sha256: String
        let nonce: String
    }

    let schema: String
    let issuer: String
    let audience: String
    let provider: String
    let model: String
    let mode: String
    let project_id: String
    let run_id: String
    let created_at: Int64
    let expires_at: Int64
    let assignments: [Assignment]

    func validateTime() throws {
        let now = Int64(Date().timeIntervalSince1970)
        guard created_at > 0, created_at <= now, expires_at > now,
              expires_at - created_at <= 900 else { throw ApprovalError.invalid }
    }

    func validate(_ expectedIssuer: String, _ expectedAudience: String) throws {
        try validateTime()
        guard schema == "agent-harness.t2scan.astra-direct.v1", issuer == expectedIssuer,
              audience == expectedAudience, provider == "codex", model == "gpt-6-astra", mode == "direct",
              matches(issuer, "[a-z0-9][a-z0-9.-]{0,63}"), matches(audience, "[a-z0-9][a-z0-9.-]{0,63}"),
              matches(project_id, "prj_[A-Za-z0-9_-]{4,64}"), matches(run_id, "run_[A-Za-z0-9_-]{4,64}"),
              assignments.count == roles.count, Set(assignments.map(\.assignment)) == Set(roles.keys),
              Set(assignments.map(\.work_item_id)).count == roles.count,
              Set(assignments.map(\.nonce)).count == roles.count,
              assignments.map(\.work_item_id) == assignments.map(\.work_item_id).sorted() else {
            throw ApprovalError.invalid
        }
        for item in assignments {
            guard matches(item.work_item_id, "wrk_[A-Za-z0-9_-]{4,64}"), matches(item.nonce, "[a-f0-9]{64}"),
                  matches(item.packet_sha256, "[a-f0-9]{64}") else { throw ApprovalError.invalid }
            let scope = try JSONEncoder().encode([project_id, run_id, item.work_item_id])
            let digest = SHA256.hash(data: scope).prefix(16).map { String(format: "%02x", $0) }.joined()
            guard item.task_key == "t2scan-audit-\(digest)-astra-direct" else { throw ApprovalError.invalid }
        }
    }

    var approvalDetails: String {
        let expiry = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: Double(expires_at)))
        let items = assignments.map { "\(roles[$0.assignment] ?? "") (\($0.work_item_id))\nPacket SHA-256 \($0.packet_sha256)" }
        return (["\(model) on \(audience)", "Issuer \(issuer)", "Project \(project_id)", "Audit \(run_id)"] +
                items + ["Expires \(expiry)"]).joined(separator: "\n\n")
    }
}

private func limitedFile(_ path: String, maximum: Int, privateOwner: Bool = false) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw ApprovalError.invalid }
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    defer { try? file.close() }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
          info.st_size > 0, info.st_size <= maximum,
          !privateOwner || (info.st_uid == geteuid() && (info.st_mode & 0o077) == 0 && info.st_nlink == 1),
          let bytes = try file.read(upToCount: maximum + 1), bytes.count == info.st_size else {
        throw ApprovalError.invalid
    }
    return bytes
}

private func parse(_ path: String, issuer: String, audience: String) throws -> (Challenge, Data) {
    let bytes = try limitedFile(path, maximum: 4096)
    let challenge = try JSONDecoder().decode(Challenge.self, from: bytes)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    // Exact canonical comparison rejects unknown fields, duplicate keys, and alternate encodings.
    guard try encoder.encode(challenge) == bytes else { throw ApprovalError.invalid }
    try challenge.validate(issuer, audience)
    return (challenge, bytes)
}

@available(macOS 13, *)
private func approve(_ reason: String) async throws -> LAContext {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedCancelTitle = "Cancel audit approval"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    guard SecureEnclave.isAvailable, context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
          context.biometryType == .touchID else { throw ApprovalError.hardwareUnavailable }
    guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
        throw ApprovalError.cancelled
    }
    return context
}

@available(macOS 14, *)
@MainActor
private func confirmScope(_ challenge: Challenge) throws {
    NSApplication.shared.setActivationPolicy(.accessory)
    NSApplication.shared.activate()
    let alert = NSAlert()
    alert.messageText = "Approve three T2Scan reviews?"
    alert.informativeText = challenge.approvalDetails
    alert.addButton(withTitle: "Continue to Touch ID").keyEquivalent = ""
    alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
    guard alert.runModal() == .alertFirstButtonReturn else { throw ApprovalError.cancelled }
}

@available(macOS 14, *)
@main
private enum OperatorSigner {
    @MainActor
    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())
        do {
            if args.count == 4, args[0] == "check" {
                _ = try parse(args[1], issuer: args[2], audience: args[3])
                print("valid challenge")
            } else if args.count == 4, args[0] == "enroll",
                      matches(args[2], "[a-z0-9][a-z0-9.-]{0,63}"),
                      matches(args[3], "[a-z0-9][a-z0-9.-]{0,23}-[a-f0-9]{32}") {
                let context = try await approve("Enroll T2Scan operator key \(args[2]) for \(args[3]).")
                defer { context.invalidate() }
                guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                               [.privateKeyUsage, .biometryCurrentSet], nil) else {
                    throw ApprovalError.hardwareUnavailable
                }
                let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl, authenticationContext: context)
                let enrollment = Enrollment(issuer: args[2], audience: args[3], keyHandle: key.dataRepresentation)
                umask(0o077)
                try JSONEncoder().encode(enrollment).write(to: URL(fileURLWithPath: args[1]), options: .withoutOverwriting)
                print(key.publicKey.pemRepresentation)
            } else if args.count == 4, args[0] == "sign" {
                let enrollmentBytes = try limitedFile(args[2], maximum: 8192, privateOwner: true)
                let enrollment = try JSONDecoder().decode(Enrollment.self, from: enrollmentBytes)
                let (challenge, bytes) = try parse(args[1], issuer: enrollment.issuer, audience: enrollment.audience)
                try confirmScope(challenge)
                try challenge.validateTime()
                let context = try await approve("Approve the three displayed Astra reviews for T2Scan audit \(challenge.run_id).")
                defer { context.invalidate() }
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: enrollment.keyHandle, authenticationContext: context)
                try challenge.validateTime()
                let signature = try key.signature(for: signatureDomain + bytes).derRepresentation
                try challenge.validateTime()
                umask(0o077)
                try signature.write(to: URL(fileURLWithPath: args[3]), options: .withoutOverwriting)
            } else {
                throw ApprovalError.invalid
            }
        } catch {
            FileHandle.standardError.write(Data("T2Scan operator action refused.\n".utf8))
            exit(2)
        }
    }
}
