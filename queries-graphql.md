# Get component by purl

```
query {
  getComponent(purl: "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.2.6.RELEASE?type=jar") {
    name
    group
    version
  }
}
```

Query using regex

```
query {
  queryComponent(filter: {group: {regexp: "/.*spring.*/"}}) {
    name
    group
    version
    description
  }
}
```

```
query {
  queryComponent(filter: {group: {regexp: "/.*debian.*/"}}) {
    name
    group
    version
  }
}
```

Fulltext search

```
query {
  queryComponent(filter: {description: {anyoftext: "spring"}}) {
    name
    group
    version
    description
  }
}
```

Debian or Ubuntu components

```
query {
  queryComponent(filter: {
    group: {allofterms: "debian"},
    or: {group: {allofterms: "ubuntu"}}
  }) @cascade {
    name
    group
    version
    purl
    vulnerabilities {
      id
      severity
      cvss_score
      description
      version
      fix_version
    }
  }
}
```

# Get Bom and components

```
query {
  getBom(serialNumber: "urn:uuid:baa5bebc-5e54-496f-a1d5-bbeba646c70f") {
    serialNumber,
    components {
      name
      group
      purl
    }
  }
}
```

Get Bom including the metadata

```
query {
  getBom(serialNumber: "urn:uuid:d28eb2da-b9a9-490d-927c-7ad283791802") {
    serialNumber,
    metadata {
      timestamp
      component {
        name
        group
        purl
      }
    }
    components {
      name
      group
      purl
    }
  }
}
```

Bom and licenses of components

```
query {
  getBom(serialNumber: "urn:uuid:baa5bebc-5e54-496f-a1d5-bbeba646c70f") {
    serialNumber,
    metadata {
      timestamp
      component {
        isRoot
        name
        group
        purl
      }
    }
    components {
      name
      group
      purl
      licenses {
        id
        name
        expression
      }
    }
  }
}
```

# Get Bom, components and vulnerabilities

```
query {
  getBom(serialNumber: "urn:uuid:b7886ffe-5e69-4637-9612-91ee3dd00040") {
    serialNumber,
    components {
      name
      group
      purl
      vulnerabilities {
        id
        severity
        cvss_score
        short_description
        version
        fix_version
      }
    }
  }
}
```

# Query by severity

```
query {
  queryVulnerability(filter: {severity: {in: [critical, high]}}) {
    id
    severity
    cvss_score
    description
    version
    fix_version
    affects {
      purl
      name
      group
    }
  }
}
```

Query by cvss_score and order by score in descending

```
query {
  queryVulnerability(filter: {cvss_score: {gt: 5.0}}, order: {desc: cvss_score}) {
    id
    severity
    cvss_score
    description
    version
    fix_version
    affects {
      purl
      name
      group
    }
  }
}
```

For components with critical and high vulnerabilities, list other vulnerabilities

```
query {
  queryVulnerability(first: 10, filter: {severity: {in: [critical, high]}}) {
    id
    severity
    cvss_score
    description
    version
    fix_version
    affects @cascade {
      purl
      name
      group
      vulnerabilities {
        id
        severity
        cvss_score
        description
        version
        fix_version
      }
    }
  }
}
```

Same as above with a vulnerability filter

```
query {
  queryVulnerability(first: 10, filter: {severity: {in: [critical, high]}}) {
    id
    severity
    cvss_score
    description
    version
    fix_version
    affects @cascade {
      purl
      name
      group
      vulnerabilities(filter: {cvss_score: {gt: 5.0}}) {
        id
        severity
        cvss_score
        description
        version
        fix_version
      }
    }
  }
}
```

Components with Vulnerabilities prioritized

```
query {
  queryComponent(first:10) @cascade {
    name
    group
    version
    purl
    appearsIn {
      serialNumber
      metadata {
        component {
          name
          group
          purl
        }
      }
    }
    vulnerabilities(filter: {has: properties} ) {
      id
      severity
      cvss_score
      description
      version
      fix_version
      properties(filter: {
                   name: {allofterms: "depscan:prioritized"},
                   and: {value: {allofterms: "true"}}
                }) {
        name
        value
      }
    }
  }
}
```

Components with Vulnerabilities prioritized and exploits

```
query {
  queryComponent(first:10) @cascade {
    name
    group
    version
    purl
    appearsIn {
      serialNumber
      metadata {
        component {
          name
          group
          purl
        }
      }
    }
    vulnerabilities(filter: {has: properties} ) {
      id
      severity
      cvss_score
      description
      version
      fix_version
      analysis(filter: {state: {allofterms: "exploitable"}}) {
        state
        detail
      }
      properties(filter: {
                   name: {allofterms: "depscan:prioritized"},
                   and: {value: {allofterms: "true"}}
                }) {
        name
        value
      }
    }
  }
}
```

Components with critical and high exploitable vulnerabilities

```
query {
  queryComponent(first:10) @cascade {
    name
    group
    version
    purl
    appearsIn {
      serialNumber
      metadata {
        component {
          purl
          name
        }
      }
    }
    vulnerabilities(filter: {
        has: properties,
        and: {severity: {in: [critical, high]}}
      }) {
      id
      severity
      cvss_score
      description
      version
      fix_version
      analysis(filter: {state: {allofterms: "exploitable"}}) {
        state
        detail
      }
    }
  }
}
```
