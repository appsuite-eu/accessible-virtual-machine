//
//  ClientRequirement.swift
//  AVMUSBHelper
//
//  Who may talk to the root USB helper: AVM, signed by the same team
//  that signed this helper.
//
//  Why the helper's own team and not a team written into the source:
//  the helper and AVM are always signed together, in one build. The
//  author's Debug builds are signed by the development team and shipped
//  builds by the Developer ID team, so this trusts exactly what the old
//  hard-coded pair trusted, and a release helper still never trusts the
//  development team. A contributor's build is signed by their own team
//  and works without editing this file (2026-11-20).
//
//  Fails closed: a helper with no team (ad-hoc or unsigned) gets no
//  requirement, and the listener then refuses every connection.
//

import Foundation
import Security

nonisolated enum ClientRequirement {

    /// An Apple team identifier: ten upper-case letters or digits. Checked
    /// before it goes into the requirement string, so nothing read from a
    /// signature can change the requirement's meaning.
    static func isValidTeamID(_ teamID: String) -> Bool {
        teamID.utf8.count == 10 && teamID.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
        }
    }

    /// The code signing requirement for AVM signed by `teamID`, or nil
    /// if the team identifier is not well formed.
    static func requirement(teamID: String) -> String? {
        guard isValidTeamID(teamID) else { return nil }
        return "anchor apple generic"
            + " and identifier \"\(AVMUSBHelperNames.clientBundleIdentifier)\""
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// The team that signed `code`, or nil for ad-hoc or unsigned code.
    static func teamID(of code: SecStaticCode) -> String? {
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              isValidTeamID(team)
        else { return nil }
        return team
    }

    /// The team that signed the running process, or nil.
    static func ownTeamID() -> String? {
        var running: SecCode?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(running, [], &staticCode) == errSecSuccess,
              let staticCode
        else { return nil }
        return teamID(of: staticCode)
    }
}
