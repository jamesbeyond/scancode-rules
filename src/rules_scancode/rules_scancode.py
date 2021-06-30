# Copyright (c) 2021 Arm Limited
# SPDX-License-Identifier: Apache-2.0

from os.path import exists
from os.path import isdir
import logging
import re
import sys
import saneyaml

from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl
from commoncode.cliutils import PluggableCommandLineOption
from commoncode.cliutils import POST_SCAN_GROUP


logging.basicConfig(format='%(levelname)s : %(message)s')
logging.getLogger().setLevel(logging.INFO)


def load_license_rules(license_rules_file):
    """
    Return a license_policy dictionary loaded from a license policy file.
    """
    if not license_rules_file or not exists(license_rules_file):
        return {}
    elif isdir(license_rules_file):
        return {}
    with open(license_rules_file, 'r') as conf:
        conf_content = conf.read()
    return saneyaml.load(conf_content)

@post_scan_impl
class ValidateRules(PostScanPlugin):
    """
    Illustrate a simple "Hello World" post-scan plugin.
    """

    options = [
        PluggableCommandLineOption(('--rules',),
            multiple=False,
            metavar='FILE',
            help='Load a License Rules file and apply it to the scan at the '
                 'Resource level.',
            help_group=POST_SCAN_GROUP)
    ]

    def is_enabled(self, rules, **kwargs):
        return rules

    def process_codebase(self, codebase, rules, **kwargs):
        """
        Say hello.
        """
        if not self.is_enabled(rules):
            return

        print(f'Using rule {rules} to validate ScanCode results.')

        # get a list of unique license policies from the license_policy file
        license_rules = load_license_rules(rules).get('license_validation_rules', [])
        log_level = load_license_rules(rules).get('log_level')
        if  log_level=="DEBUG":
            logging.getLogger().setLevel(logging.DEBUG)
        elif log_level=="QUIET":
            logging.getLogger().setLevel(logging.WARNING)

        # Check every resources entry if they contain an offending rules
        for resource in codebase.walk(topdown=True):
            if not resource.is_file:
                continue
            logging.debug(f"Check entry {resource.path}")

            for rule in license_rules:
                logging.debug(f" - Validate rule '{rule.get('rule')}'")
                if re.search(rule.get('path_regex'), resource.path):
                    if key := rule.get('license_key'):
                        resource_keys = set([entry.get('key') for entry in resource.licenses])
                        logging.debug(f"   - Check if license_key '{key}' in {resource_keys}")
                        if not key in resource_keys:
                            logging.debug("     - Not Matching")
                            continue # not match skip to next rule
                    if category := rule.get('license_category'):
                        resource_categories = set([entry.get('category') for entry in resource.licenses])
                        logging.debug(f"   - Check if license_category '{category}' in {resource_categories}")
                        if not category in resource_categories:
                            logging.debug("     - Not Matching")
                            continue # not match skip to next rule

                    if rule.get('verdict') == 'pass':
                        logging.info(f"PASSED: { rule.get('rule') } - {resource.path}")
                        break # matched a rule, skip all rest of rules
                    elif rule.get('verdict') == 'fail':
                        logging.error(f"FAILED: { rule.get('rule') } - {resource.path}")
                        codebase.errors.append(f"FAILED: offending {rule.get('rule')} - {resource.path}\n")
                        break # matched a rule, skip all rest of rules
                    elif rule.get('verdict') == 'warn':
                        logging.warning(f"{ rule.get('rule') } - {resource.path}")
                        codebase.errors.append(f"WARNING: {rule.get('rule')} - {resource.path}\n")
                        break # matched a rule, skip all rest of rules
                    else:
                        sys.exit(f"Not a valid verdict {rule.get('verdict')}")
            else:
                logging.warning(f"NOT MATCH ANY RULE, IGNORED - {resource.path}")
