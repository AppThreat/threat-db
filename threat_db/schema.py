graphql_schema = """
type User @secret(field: "password") {
    id: String! @id
    email: String! @search(by: [term])
    fullName: String! @search(by: [term, fulltext])
    created: DateTime
    modified: DateTime
    teams: [Team]
    roles: [UserRole]
    disabled: Boolean
}
type Team {
    id: String! @id
    name: String! @search(by: [term])
    description: String @search(by: [term, fulltext])
    tags: [String]
    users: [User] @hasInverse(field: teams)
    applications: [Application] @hasInverse(field: teams)
    created: DateTime
    modified: DateTime
    disabled: Boolean
}
type UserRole {
    id: String! @id
    user: User!
    team: Team!
    role: String!
    created: DateTime
    modified: DateTime
    disabled: Boolean
}
type ScanResult {
    id: String! @id
    scan: Scan
    created: DateTime
    validUntil: DateTime
    bom: [Bom]
    components: [Component]
    vulnerabilities: [Vulnerability]
    prioritizedComponents: [Component]
    prioritizedVulnerabilities: [Vulnerability]
    exploitableComponents: [Component]
    exploitableVulnerabilities: [Vulnerability]
    ignoredComponents: [Component]
    ignoredVulnerabilities: [Vulnerability]
    url: String
    htmlUrl: String
    csvUrl: String
    pdfUrl: String
}
type Scan {
    id: String! @id
    isScheduled: Boolean
    invokedBy: User
    created: DateTime
    validUntil: DateTime
    applications: [Application]
    tags: [String]
    result: ScanResult @hasInverse(field: scan)
    url: String
}
type Environment {
    id: String! @id
    name: String! @search(by: [term])
    description: String @search(by: [term, fulltext])
    tags: [String]
    url: String
    users: [User]
    teams: [Team]
}
type ApplicationVersion {
    branch: String
    release: String
    tag: String
}
type Application {
    id: String! @id
    name: String! @search(by: [term, regexp])
    description: String @search(by: [term, fulltext])
    environment: Environment
    version: ApplicationVersion
    repoUrl: String
    issuesUrl: String
    ciUrl: String
    cdUrl: String
    changeManagementUrl: String
    languages: [String]
    frameworks: [String]
    classification: [String]
    tags: [String]
    created: DateTime
    modified: DateTime
    teams: [Team]
    disabled: Boolean
}
type Properties {
    name: String! @search(by: [term, fulltext])
    value: String! @search(by: [term, fulltext])
}
type BomMetadata {
    timestamp: DateTime!
    component: Component
}
type ComponentLicense {
    id: String @search(by: [hash])
    name: String
    text: String
    url: String
    expression: String
}
type Component {
    isRoot: Boolean
    bomRef: String!
    group: String! @search(by: [term, regexp])
    name: String! @search(by: [term, regexp])
    description: String @search(by: [term, fulltext])
    ctype: String
    subPath: String
    repoUrl: String
    downloadUrl: String
    publisher: String
    licenses: [ComponentLicense]
    scope: String @search(by: [exact])
    version: String! @search(by: [term, regexp])
    purl: String! @id @search(by: [term, regexp])
    vulnerabilities: [Vulnerability] @hasInverse(field: affects)
    properties: [Properties]
    dependency: [Component]
    appearsIn: [Bom] @hasInverse(field: components)
}
type BomServiceData {
    data: String
    flow: [String]
    classification: [String]
}
type BomService {
    bomRef: String!
    group: String! @search(by: [term, regexp])
    name: String! @search(by: [term, regexp])
    version: String! @search(by: [term, regexp])
    description: String @search(by: [term, fulltext])
    endpoints: [String] @search(by: [term])
    authenticated: Boolean
    xTrustBoundary: Boolean
    data: [BomServiceData]
    licenses: [ComponentLicense]
    services: [BomService]
    properties: [Properties]
}
type Bom {
    serialNumber: String! @id @search(by: [hash])
    metadata: BomMetadata
    components: [Component!]!
    services: [BomService]
    application: Application
    scan: Scan
    vulnerabilities: [Vulnerability]
}
enum Severity {
    critical
    high
    medium
    low
    info
    none
    unknown
}
enum VulnerabilityVersionStatusEnum {
    affected
    unaffected
}
type VulnerabilityVersionChanges {
    at: String!
    status: VulnerabilityVersionStatusEnum!
}
type VulnerabilityVersionStatus {
    version: String!
    versionType: String
    repo: String
    lessThanOrEqual: String
    lessThan: String
    changes: [VulnerabilityVersionChanges]
    status: VulnerabilityVersionStatusEnum!
}
type VulnerabilityDetail {
    vulnerability: Vulnerability!
    title: String @search(by: [term])
    summary: String @search(by: [term, fulltext])
    datePublic: DateTime
    collectionURL: String
    defaultStatus: String
    descriptions: [String]
    modules: [String]
    programFiles: [String]
    programRoutines: [String]
    platforms: [String]
    versions: [VulnerabilityVersionStatus]
    solutions: [String]
    workarounds: [String]
    configurations: [String]
    exploits: [String]
    timeline: [String]
    credits: [String]
    references: [String]
    source: String
}
type VulnerabilitySource {
    name: String @search(by: [term])
    url: String
}
type VulnerabilityAdvisory {
    title: String @search(by: [term])
    url: String
}
type VulnerabilityRating {
    severity: Severity! @search(by: [hash])
    score: Float! @search
    method: String
}
type VulnerabilityAnalysis {
    state: String @search(by: [hash, term])
    detail: String @search(by: [term, fulltext])
}
type Vulnerability {
    bomRef: String! @id @search(by: [hash])
    id: String! @search(by: [hash, term])
    source: VulnerabilitySource
    ratings: [VulnerabilityRating]
    severity: Severity! @search(by: [hash])
    cvss_score: Float! @search
    cwes: [Int]
    description: String @search(by: [fulltext])
    recommendation: String @search(by: [fulltext])
    advisories: [VulnerabilityAdvisory]
    analysis: VulnerabilityAnalysis
    affects: [Component]
    version: String! @search(by: [term, regexp])
    fix_version: String @search(by: [term, regexp])
    properties: [Properties]
    detail: VulnerabilityDetail @hasInverse(field: vulnerability)
}
"""
