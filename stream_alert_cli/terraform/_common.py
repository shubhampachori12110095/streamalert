"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from collections import defaultdict


DEFAULT_SNS_MONITORING_TOPIC = 'stream_alert_monitoring'


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass


def infinitedict():
    """Create arbitrary levels of dictionary key/values"""
    return defaultdict(infinitedict)


def enabled_firehose_logs(config):
    """Return a list of enabled log types via sources.json

    Args:
        config (CLIConfig): The loaded configuration

    Returns:
        list: All enabled logs sending to StreamAlert
    """
    config_logs = set(config['logs'])
    disabled_logs = set(config['global']['infrastructure'].get(
        'firehose', {}).get('disabled_logs', []))
    expanded_logs_with_subtypes = set()
    enabled_logs_from_sources = list()

    for entities in config['sources'].values():
        for properties in entities.values():
            enabled_logs_from_sources.extend(properties['logs'])

    for log in config_logs:
        for enabled_log in set(enabled_logs_from_sources) - disabled_logs:
            log_type = log.split(':')[0]
            if log_type == enabled_log:
                expanded_logs_with_subtypes.add(log)

    # Firehose Delivery Streams cannot have semicolons
    filtered_log_names = [log.replace(':', '_') for log in expanded_logs_with_subtypes]
    return sorted(filtered_log_names)
