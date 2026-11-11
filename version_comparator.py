#!/usr/bin/env python3
"""
native_scanner/version_comparator.py
====================================
Pure-Python Enterprise Linux Distribution & Package Version Comparator.
Implements exact version comparison logic matching dpkg, rpmvercmp, and apk:
- Debian/Ubuntu: debian epoch:upstream_version-debian_revision (dpkg --compare-versions)
- RedHat/CentOS/Fedora/Amazon Linux: RPM epoch:version-release (rpmvercmp algorithm)
- Alpine Linux: APK semantic versioning with alpha/beta/pre/rc/patch suffixes

Eliminates false positives on enterprise backported security patches.
Zero external dependencies.
"""

import re
from typing import Optional, Tuple


# ==============================================================================
# 1. Debian / Ubuntu Package Version Comparator (dpkg standard)
# ==============================================================================

def debian_split_version(version_str: str) -> Tuple[int, str, str]:
    """
    Splits a Debian version string into (epoch, upstream_version, debian_revision).
    Format: [epoch:]upstream_version[-debian_revision]
    """
    version_str = version_str.strip()
    epoch = 0
    if ":" in version_str:
        epoch_part, remainder = version_str.split(":", 1)
        try:
            epoch = int(epoch_part)
        except ValueError:
            epoch = 0
        version_str = remainder

    if "-" in version_str:
        upstream, revision = version_str.rsplit("-", 1)
    else:
        upstream = version_str
        revision = "0"

    return epoch, upstream, revision


def _dpkg_order_char(c: str) -> int:
    """Returns sort order for characters according to dpkg spec."""
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    # Any other character sorts after alphabetics
    return ord(c) + 256


def dpkg_compare_strings(s1: str, s2: str) -> int:
    """
    Compares two string components under Debian version comparison rules:
    - Digits compared numerically.
    - Non-digits compared with '~' sorting before everything, including empty string.
    """
    i, j = 0, 0
    len1, len2 = len(s1), len(s2)

    while i < len1 or j < len2:
        # First compare non-digit characters
        while (i < len1 and not s1[i].isdigit()) or (j < len2 and not s2[j].isdigit()):
            c1 = s1[i] if i < len1 and not s1[i].isdigit() else ""
            c2 = s2[j] if j < len2 and not s2[j].isdigit() else ""
            o1 = _dpkg_order_char(c1)
            o2 = _dpkg_order_char(c2)
            if o1 != o2:
                return -1 if o1 < o2 else 1
            if i < len1 and not s1[i].isdigit():
                i += 1
            if j < len2 and not s2[j].isdigit():
                j += 1

        # Next compare digit sequences numerically
        num1_str = ""
        while i < len1 and s1[i].isdigit():
            num1_str += s1[i]
            i += 1

        num2_str = ""
        while j < len2 and s2[j].isdigit():
            num2_str += s2[j]
            j += 1

        if num1_str or num2_str:
            n1 = int(num1_str) if num1_str else 0
            n2 = int(num2_str) if num2_str else 0
            if n1 != n2:
                return -1 if n1 < n2 else 1

    return 0


def compare_debian_versions(v1: str, v2: str) -> int:
    """
    Returns:
      -1 if v1 < v2
       0 if v1 == v2
       1 if v1 > v2
    """
    e1, u1, r1 = debian_split_version(v1)
    e2, u2, r2 = debian_split_version(v2)

    if e1 != e2:
        return -1 if e1 < e2 else 1

    cmp_upstream = dpkg_compare_strings(u1, u2)
    if cmp_upstream != 0:
        return cmp_upstream

    return dpkg_compare_strings(r1, r2)


# ==============================================================================
# 2. RedHat / CentOS / RPM Version Comparator (rpmvercmp standard)
# ==============================================================================

def rpmvercmp(a: str, b: str) -> int:
    """
    Pure-Python implementation of RPM's rpmvercmp algorithm.
    Splits string into contiguous alphanumeric segments and compares.
    """
    if a == b:
        return 0

    seg_regex = re.compile(r"([0-9]+|[a-zA-Z]+|~)")
    segs1 = seg_regex.findall(a)
    segs2 = seg_regex.findall(b)

    for s1, s2 in zip(segs1, segs2):
        if s1 == "~" or s2 == "~":
            if s1 == "~" and s2 != "~":
                return -1
            if s1 != "~" and s2 == "~":
                return 1
            continue

        if s1.isdigit() and s2.isdigit():
            n1, n2 = int(s1), int(s2)
            if n1 != n2:
                return -1 if n1 < n2 else 1
        elif not s1.isdigit() and not s2.isdigit():
            if s1 != s2:
                return -1 if s1 < s2 else 1
        else:
            # Numeric segments are always newer than alpha segments
            return 1 if s1.isdigit() else -1

    if len(segs1) != len(segs2):
        if len(segs1) > len(segs2):
            return -1 if segs1[len(segs2)] == "~" else 1
        else:
            return 1 if segs2[len(segs1)] == "~" else -1

    return 0


def compare_rpm_versions(v1: str, v2: str) -> int:
    """Splits RPM epoch:version-release and compares with rpmvercmp."""
    def parse_rpm(v):
        epoch = 0
        if ":" in v:
            ep_str, rest = v.split(":", 1)
            try:
                epoch = int(ep_str)
            except ValueError:
                epoch = 0
            v = rest
        if "-" in v:
            ver, rel = v.split("-", 1)
        else:
            ver, rel = v, "0"
        return epoch, ver, rel

    e1, ver1, rel1 = parse_rpm(v1)
    e2, ver2, rel2 = parse_rpm(v2)

    if e1 != e2:
        return -1 if e1 < e2 else 1
    cmp_v = rpmvercmp(ver1, ver2)
    if cmp_v != 0:
        return cmp_v
    return rpmvercmp(rel1, rel2)


# ==============================================================================
# 3. Alpine Linux (APK) Version Comparator
# ==============================================================================

_APK_SUFFIX_ORDER = {
    "alpha": 1,
    "beta": 2,
    "pre": 3,
    "rc": 4,
    "": 5,
    "cvs": 6,
    "svn": 7,
    "git": 8,
    "hg": 9,
    "p": 10,
    "patch": 11,
}


def compare_apk_versions(v1: str, v2: str) -> int:
    """Compares Alpine apk version strings (e.g., 1.2.3_rc1-r2 vs 1.2.3-r0)."""
    def tokenize(v: str):
        v = v.split("-r")[0]  # ignore revision for base tokenization
        parts = re.split(r"[._]", v)
        tokens = []
        for p in parts:
            if p.isdigit():
                tokens.append((0, int(p)))
            else:
                m = re.match(r"^([a-zA-Z]+)(\d*)$", p)
                if m:
                    sfx = m.group(1).lower()
                    num = int(m.group(2)) if m.group(2) else 0
                    rank = _APK_SUFFIX_ORDER.get(sfx, 0)
                    tokens.append((rank, num))
                else:
                    tokens.append((0, p))
        return tokens

    t1 = tokenize(v1)
    t2 = tokenize(v2)

    for p1, p2 in zip(t1, t2):
        if p1 != p2:
            return -1 if p1 < p2 else 1

    if len(t1) != len(t2):
        if len(t1) > len(t2):
            extra = t1[len(t2)]
            if isinstance(extra, tuple) and extra[0] < 5:
                return -1
            return 1
        else:
            extra = t2[len(t1)]
            if isinstance(extra, tuple) and extra[0] < 5:
                return 1
            return -1

    # Compare Alpine '-rX' revisions if base matches
    r1 = 0
    if "-r" in v1:
        try:
            r1 = int(v1.split("-r")[-1])
        except ValueError:
            r1 = 0
    r2 = 0
    if "-r" in v2:
        try:
            r2 = int(v2.split("-r")[-1])
        except ValueError:
            r2 = 0

    if r1 != r2:
        return -1 if r1 < r2 else 1
    return 0


# ==============================================================================
# 4. Universal Unified Linux Package Comparator
# ==============================================================================

class LinuxVersionComparator:
    """Universal package version comparator dispatching based on distro ecosystem."""

    @staticmethod
    def is_vulnerable(installed_version: str, fixed_version: str, distro_type: str = "generic") -> bool:
        """
        Determines if installed_version is strictly less than fixed_version (< fixed_version).
        Returns True if installed is vulnerable, False if patched or equal/newer.
        """
        if not installed_version or not fixed_version:
            return False

        distro = distro_type.lower()
        try:
            if "debian" in distro or "ubuntu" in distro:
                return compare_debian_versions(installed_version, fixed_version) < 0
            elif "rhel" in distro or "centos" in distro or "fedora" in distro or "rpm" in distro or "amazon" in distro:
                return compare_rpm_versions(installed_version, fixed_version) < 0
            elif "alpine" in distro or "apk" in distro:
                return compare_apk_versions(installed_version, fixed_version) < 0
            else:
                # Fallback to debian/dpkg string rules (closest to universal semver)
                return compare_debian_versions(installed_version, fixed_version) < 0
        except Exception:
            return installed_version != fixed_version
