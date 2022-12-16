# Find components with group spring

```
{
 find_spring(func: eq(group, "org.springframework.boot")) {
   group,
   name,
   version,
   purl
 }
}
```

# Find components with group spring with the original bom

```
{
 find_spring(func: eq(group, "org.springframework.boot")) {
   uid,
   group,
   name,
   version,
   purl,
   bom {
     uid
     components {
      bom-ref
      group
      name
      version
    }
  }
 }
}
```

# Find spring with regexp search

```
{
 find_spring(func: regexp(group, /.*spring.*/)) {
   uid,
   group,
   name,
   version,
   purl,
 }
}
```

# Find spring with RELEASE version

```
{
 find_spring(func: regexp(group, /.*spring.*/)) @filter(regexp(version, /.*RELEASE.*/)) {
		name,
    group,
    version,
    purl
 }
}
```

# Find spring with RELEASE version and has licenses

```
{
 find_spring(func: regexp(group, /.*spring.*/)) @filter(regexp(version, /.*RELEASE.*/) AND has(licenses)) {
		name,
    group,
    version,
    purl,
    licenses
 }
}
```

# Find spring with RELEASE version and optional scope

```
{
 find_spring(func: regexp(group, /.*spring.*/)) @filter(regexp(version, /.*RELEASE.*/) AND eq(scope, "optional")) {
		name,
    group,
    version,
    purl,
    licenses,
  	scope
 }
}
```

# Find spring with RELEASE version and required scope and Apache-2.0 license

```
{
 find_spring(func: regexp(group, /.*spring.*/)) @filter(regexp(version, /.*RELEASE.*/) AND eq(scope, "required") AND has(licenses) AND eq(licenses, "Apache-2.0")) {
		name,
    group,
    version,
    purl,
    licenses,
  	scope
 }
}
```

`AND has(licenses)` could be dropped to simplify this query

# Find spring with RELEASE version and required scope and not Apache-2.0 license

```
{
 find_spring(func: regexp(group, /.*spring.*/)) @filter(regexp(version, /.*RELEASE.*/) AND eq(scope, "required") AND has(licenses) AND NOT eq(licenses, "Apache-2.0")) {
		name,
    group,
    version,
    purl,
    licenses,
  	scope
 }
}
```

Navigate from vulns

```
{
	find_vulns(func: gt(cvss_score, 8)) {
    uid
    id
    severity
    cvss_score
    purl
    short_description,
    components {
      uid
			name
      group
      version
      purl
    }
  }
}
```

# Find spring vulnerabilities

```
{
 find_spring(func: eq(group, "org.springframework.boot")) {
   uid,
   group,
   name,
   version,
   purl,
   vulnerabilities @facets {
	   id
     severity
     cvss_score
     short_description
     fix_version
   }
  }
}
```

# Find bom vulns (Not working)

```
{
 find_bom(func: eq(serialNumber, "_:baa5bebc-5e54-496f-a1d5-bbeba646c70f")) {
  serialNumber
  components {
		purl
    name
    group
    version
    vulnerabilities {
			id
      severity
      cvss_score
      short_description
      fix_version
    }
  }
 }
}
```

# Packages with vulns (Not working)

```
{
 find_pkgs(func: has(vulnerabilities)) {
   uid,
   group,
   name,
   version,
   purl,
   vulnerabilities @facets {
	   id
     severity
     cvss_score
     short_description
     fix_version
   }
  }
}
```
