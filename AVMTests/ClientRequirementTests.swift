//
//  ClientRequirementTests.swift
//  AVMTests
//
//  The root helper's gate: AVM, signed by the helper's own team.
//

import Foundation
import Security
import Testing

@Suite("Helper client requirement")
struct ClientRequirementTests {

    @Test("accepts well-formed team identifiers", arguments: ["4NZJSBJ32X", "W7VP84KBHP", "ABCDE12345"])
    func validTeams(team: String) {
        #expect(ClientRequirement.isValidTeamID(team))
    }

    @Test("rejects anything that is not ten upper-case letters or digits",
          arguments: ["", "4NZJSBJ32", "4NZJSBJ32XY", "4nzjsbj32x", "4NZJSBJ32-", "ÉNZJSBJ32X",
                      "X\" or anchor apple", "4NZJSBJ32X\"", " 4NZJSBJ32"])
    func invalidTeams(team: String) {
        #expect(!ClientRequirement.isValidTeamID(team))
        #expect(ClientRequirement.requirement(teamID: team) == nil)
    }

    @Test("names AVM's bundle identifier and the team")
    func requirementText() throws {
        let text = try #require(ClientRequirement.requirement(teamID: "ABCDE12345"))
        #expect(text == "anchor apple generic and identifier \"com.alllisonmeloy.AVM\" and certificate leaf[subject.OU] = \"ABCDE12345\"")
    }

    @Test("macOS accepts the requirement string")
    func requirementCompiles() throws {
        let text = try #require(ClientRequirement.requirement(teamID: "W7VP84KBHP"))
        var requirement: SecRequirement?
        #expect(SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess)
        #expect(requirement != nil)
    }

    @Test("ad-hoc signed code has no team, so the gate fails closed")
    func adHocHasNoTeam() throws {
        // This test bundle is signed ad hoc ("-"), like a helper built
        // without a real identity.
        let url = Bundle(for: BundleMarker.self).bundleURL
        var code: SecStaticCode?
        #expect(SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess)
        let staticCode = try #require(code)
        #expect(ClientRequirement.teamID(of: staticCode) == nil)
    }

    @Test("an Apple-signed system binary reports no developer team")
    func systemBinary() throws {
        var code: SecStaticCode?
        #expect(SecStaticCodeCreateWithPath(URL(fileURLWithPath: "/bin/ls") as CFURL, [], &code) == errSecSuccess)
        let staticCode = try #require(code)
        #expect(ClientRequirement.teamID(of: staticCode) == nil)
    }
}

/// Finds this test bundle.
private final class BundleMarker {}
