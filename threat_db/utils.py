import os

from packageurl import PackageURL
from packageurl.contrib import purl2url

import threat_db.config as config


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories
    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in config.ignore_directories or d.startswith(".")
    ]
    return dirs


def find_files(src, src_ext_name, quick=False, filter=True):
    """
    Method to find files with given extenstion
    """
    result = []
    for root, dirs, files in os.walk(src):
        if filter:
            filter_ignored_dirs(dirs)
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
                if quick:
                    return result
    return result


def parse_purl(purl_str):
    """Method to parse a package url string safely"""
    try:
        purl_obj = PackageURL.from_string(purl_str).to_dict() if purl_str else {}
        if purl_obj:
            purl_obj["repo_url"] = purl2url.get_repo_url(purl_str)
            purl_obj["download_url"] = purl2url.get_download_url(purl_str)
        return purl_obj
    except ValueError:
        tmpA = purl_str.split("@")[0]
        purl_obj = {}
        if tmpA:
            tmpB = tmpA.split("/")
            if tmpB:
                if len(tmpB) < 2:
                    purl_obj["name"] = tmpB[-1].lower()
                    purl_obj["namespace"] = tmpB[0].split(":")[-1]
                if len(tmpB) > 2:
                    namespace = tmpB[-2]
                    if tmpB[-2].startswith("pkg:"):
                        namespace = tmpB[-2].split(":")[-1]
                    purl_obj["namespace"] = namespace
        return purl_obj


def safe_remove(f):
    try:
        os.remove(f)
    except Exception as e:
        pass
