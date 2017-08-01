'''
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
'''
import json

from logging import DEBUG as log_level_debug

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.config import ConfigError, load_config, load_env
from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.metrics import Metrics
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.sink import StreamSink


class StreamAlert(object):
    """Wrapper class for handling all StreamAlert classificaiton and processing"""

    def __init__(self, context):
        """
        Args:
            context: An AWS context object which provides metadata on the currently
                executing lambda function. The environment is setup from the arn
                within the context object. For testing, the lambda alias on the arn
                will be 'development' - this dictates what to do with alerts.
        """
        # Try to load the config - validation occurs during load
        try:
            config = load_config()
        except ConfigError:
            LOGGER.exception('Error loading config files')
            raise

        # Load the environment from the context arn
        self.env = load_env(context)

        # Instantiate the sink here to handle sending the triggered alerts to the
        # alert processor
        self.sinker = StreamSink(self.env)

        # Instantiate a classifier that is used for this run
        self.classifier = StreamClassifier(config=config)

        self.metrics = Metrics(self.env['lambda_region'])
        self._failed_log_count = 0
        self._alerts = []

    def run(self, event):
        """StreamAlert Lambda function handler.

        Loads the configuration for the StreamAlert function which contains:
        available data sources, log formats, parser modes, and sinks.  Classifies
        logs sent into the stream into a parsed type.  Matches records against
        rules.

        Args:
            event: An AWS event mapped to a specific source/entity (kinesis stream or
                an s3 bucket event) containing data emitted to the stream.

        Returns:
            [integer] exit status code. 0 on success, non-zero on error
        """
        records = event.get('Records', [])
        LOGGER.debug('Number of Records: %d', len(records))
        if not records:
            return False

        self.metrics.put_metric_data(
            Metrics.Name.TOTAL_RECORDS,
            len(records),
            Metrics.Unit.COUNT)

        for raw_record in records:
            # Get the service and entity from the payload. If the service/entity
            # is not in our config, log and error and go onto the next record
            service, entity = self.classifier.extract_service_and_entity(raw_record)
            if not service:
                LOGGER.error('No valid service found in payload\'s raw record')

            if not entity:
                LOGGER.error(
                    'Unable to map entity from payload\'s raw record for service %s',
                    service)

            if not (service and entity):
                continue

            # If the payload's service and entity are found in the config and
            # contains logs then load the sources for this log
            if not self.classifier.load_sources(service, entity):
                continue

            # Create the StreamPayload to use for encapsulating parsed info
            payload = load_stream_payload(service, entity, raw_record, self.metrics)
            if not payload:
                continue

            self._process_alerts(payload)

        LOGGER.debug('Invalid log failure count: %d', self._failed_log_count)

        self.metrics.put_metric_data(
            Metrics.Name.FAILED_PARSES,
            self._failed_log_count,
            Metrics.Unit.COUNT)

        LOGGER.debug('%s alerts triggered', len(self._alerts))

        self.metrics.put_metric_data(
            Metrics.Name.TRIGGERED_ALERTS, len(
                self._alerts), Metrics.Unit.COUNT)

        if self._alerts and LOGGER.isEnabledFor(log_level_debug):
            LOGGER.debug('Alerts:\n%s', json.dumps(self._alerts, indent=2))

        return self._failed_log_count == 0

    def get_alerts(self):
        """Public method to return alerts from class. Useful for testing.

        Returns:
            [list] list of alerts in json format
        """
        return self._alerts

    def _process_alerts(self, payload):
        """Process records for alerts and send them to the correct places

        Args:
            payload [StreamPayload]: StreamAlert payload object being processed
            data [string]: Pre parsed data string from a raw_event to be parsed
        """
        is_production = self.env['lambda_alias'] != 'development'
        for record in payload.pre_parse():
            self.classifier.classify_record(record)
            if not record.valid:
                if is_production:
                    LOGGER.error('Log failed to match any defined schemas: %s\n%s',
                                 record, record.pre_parsed_record)

                self._failed_log_count += 1
                continue

            LOGGER.debug('Payload: %s', record)

            record_alerts = StreamRules.process(record)
            if not record_alerts:
                LOGGER.debug('Valid data, no alerts')
                continue

            # Extend the list of alerts with any new alerts
            self._alerts.extend(record_alerts)

            # Attempt to send them to the alert processor
            if is_production:
                self.sinker.sink(record_alerts)
